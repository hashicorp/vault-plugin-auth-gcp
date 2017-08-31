package gcpauth

import (
	"errors"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/hashicorp/vault-plugin-auth-gcp/plugin/util"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"strconv"
	"strings"
	"time"
)

const (
	expectedJwtAudTemplate string = "vault/%s"

	// Default duration that JWT tokens must expire within to be accepted
	defaultMaxJwtExpMin int = 15

	clientErrorTemplate string = "backend not configured properly, could not create %s client: %v"
)

func pathLogin(b *GcpAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. Required.`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT for authenticating a service account.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:           b.pathLogin,
			logical.PersonaLookaheadOperation: b.pathLogin,
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *GcpAuthBackend) pathLogin(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	loginInfo, err := b.parseInfoFromJwt(req, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	roleType := loginInfo.Role.RoleType
	switch roleType {
	case iamRoleType:
		return b.pathIamLogin(req, loginInfo)
	case gceRoleType:
		return b.pathGceLogin(req, loginInfo)
	default:
		return logical.ErrorResponse(fmt.Sprintf("login against role type '%s' is unsupported", roleType)), nil
	}
}

func (b *GcpAuthBackend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Check role exists and allowed policies are still the same.
	roleName := req.Auth.Metadata["role"]
	if roleName == "" {
		return logical.ErrorResponse("role name metadata not associated with auth token, invalid"), nil
	}
	role, err := b.role(req.Storage, roleName)
	if err != nil {
		return nil, err
	} else if role == nil {
		return logical.ErrorResponse("role '%s' no longer exists"), nil
	} else if !policyutil.EquivalentPolicies(role.Policies, req.Auth.Policies) {
		return logical.ErrorResponse("policies on role '%s' have changed, cannot renew"), nil
	}

	switch role.RoleType {
	case iamRoleType:
		if err := b.pathIamRenew(req, role); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	default:
		return nil, fmt.Errorf("unexpected role type '%s' for login renewal", role.RoleType)
	}

	// If 'Period' is set on the Role, the token should never expire.
	if role.Period > 0 {
		// Replenish the TTL with current role's Period.
		req.Auth.TTL = role.Period
		return &logical.Response{Auth: req.Auth}, nil
	} else {
		return framework.LeaseExtend(role.TTL, role.MaxTTL, b.System())(req, data)
	}
}

// gcpLoginInfo represents the data given to Vault for logging in using the IAM method.
type gcpLoginInfo struct {
	// Name of the role being logged in against
	RoleName string

	// Role being logged in against
	Role *gcpRole

	// ID or email of an IAM service account or that inferred for a GCE VM.
	ServiceAccountId string

	// Metadata from a GCE instance identity token.
	GceMetadata *util.GCEIdentityMetadata

	// ID of the public key to verify the signed JWT.
	KeyId string

	// Signed JWT
	JWT jwt.JWT
}

func (b *GcpAuthBackend) parseInfoFromJwt(req *logical.Request, data *framework.FieldData) (*gcpLoginInfo, error) {
	loginInfo := &gcpLoginInfo{}
	var err error

	loginInfo.RoleName = data.Get("role").(string)
	if loginInfo.RoleName == "" {
		return nil, errors.New("role is required")
	}

	loginInfo.Role, err = b.role(req.Storage, loginInfo.RoleName)
	if err != nil {
		return nil, err
	}
	if loginInfo.Role == nil {
		return nil, fmt.Errorf("role '%s' not found", loginInfo.RoleName)
	}

	signedJwt, ok := data.GetOk("jwt")
	if !ok {
		return nil, errors.New("jwt argument is required")
	}
	signedJwtBytes := []byte(signedJwt.(string))

	// Parse into JWS to get header values.
	jwsVal, err := jws.Parse(signedJwtBytes)
	if err != nil {
		return nil, err
	}
	headerVal := jwsVal.Protected()

	if headerVal.Has("kid") {
		loginInfo.KeyId = jwsVal.Protected().Get("kid").(string)
	} else {
		return nil, errors.New("provided JWT must have 'kid' header value")
	}

	// Parse claims
	loginInfo.JWT, err = jws.ParseJWT(signedJwtBytes)
	if err != nil {
		return nil, err
	}

	sub, ok := loginInfo.JWT.Claims().Subject()
	if !ok {
		return nil, errors.New("expected JWT to have 'sub' claim with service account id or email")
	}
	loginInfo.ServiceAccountId = sub

	loginInfo.GceMetadata, err = util.ParseGceIdentityMetadata(loginInfo.JWT.Claims())
	if err != nil {
		return nil, err
	}
	if loginInfo.Role.RoleType == gceRoleType && loginInfo.GceMetadata == nil {
		return nil, errors.New("expected JWT to have claims with GCE metadata")
	}

	return loginInfo, nil
}

func (info *gcpLoginInfo) validateJWT(key interface{}) error {
	validator := &jwt.Validator{
		Fn: func(c jwt.Claims) error {
			exp, ok := c.Expiration()
			if !ok {
				return errors.New("JWT claim 'exp' is required")
			}

			aud, ok := c.Audience()
			if !ok || len(aud) != 1 {
				return errors.New("expected one JWT claim 'aud'")
			}
			expectedAudSuffix := fmt.Sprintf(expectedJwtAudTemplate, info.RoleName)

			if !strings.HasSuffix(aud[0], expectedAudSuffix) {
				return errors.New("JWT claim 'aud' must end in required")
			}

			//TODO(emilymye): Remove this check for iam role type only once exp param is implemented in GCE.
			if info.Role.RoleType == iamRoleType {
				if exp.After(time.Now().Add(info.Role.MaxJwtExp)) {
					return fmt.Errorf("JWT expires in %v minutes but must expire within %v for this role. Please generate a new token with a valid expiration.",
						int(exp.Sub(time.Now())/time.Minute), info.Role.MaxJwtExp)
				}
			}

			return nil
		},
	}

	if err := info.JWT.Validate(key, crypto.SigningMethodRS256, validator); err != nil {
		return fmt.Errorf("invalid JWT: %v", err)
	}

	return nil
}

// ---- IAM login domain ----
// pathIamLogin attempts a login operation using the parsed login info.
func (b *GcpAuthBackend) pathIamLogin(req *logical.Request, loginInfo *gcpLoginInfo) (*logical.Response, error) {
	iamClient, err := b.IAM(req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(clientErrorTemplate, "IAM", err)), nil
	}

	role := loginInfo.Role
	if !role.AllowGCEInference && loginInfo.GceMetadata != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"IAM role '%s' does not allow gce inference but GCE instance metadata token given", loginInfo.RoleName)), nil
	}

	// Verify and get service account from signed JWT.
	key, err := util.ServiceAccountKey(iamClient, loginInfo.KeyId, loginInfo.ServiceAccountId, role.ProjectId)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("service account %s has no key with id %s", loginInfo.ServiceAccountId, loginInfo.KeyId)), nil
	}

	pubKey, err := util.PublicKey(key.PublicKeyData)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"unable to get public RSA key from service acount key: %v", err)), nil
	}

	if err := loginInfo.validateJWT(pubKey); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	serviceAccount, err := util.ServiceAccount(iamClient, loginInfo.ServiceAccountId, role.ProjectId)
	if err != nil {
		return nil, err
	}
	if serviceAccount == nil {
		return nil, errors.New("service account is empty")
	}

	if req.Operation == logical.PersonaLookaheadOperation {
		return &logical.Response{
			Auth: &logical.Auth{
				Persona: &logical.Persona{
					Name: serviceAccount.UniqueId,
				},
			},
		}, nil
	}

	// Validate service account can login against role.
	if err := b.validateIAMServiceAccount(serviceAccount, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Period: role.Period,
			Persona: &logical.Persona{
				Name: serviceAccount.UniqueId,
			},
			Policies: role.Policies,
			Metadata: map[string]string{
				"service_account_id":    serviceAccount.UniqueId,
				"service_account_email": serviceAccount.Email,
				"role":                  loginInfo.RoleName,
			},
			DisplayName: serviceAccount.Email,
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       role.TTL,
			},
		},
	}

	return resp, nil
}

// pathIamRenew returns an error if the service account referenced in the auth token metadata cannot renew the
// auth token for the given role.
func (b *GcpAuthBackend) pathIamRenew(req *logical.Request, role *gcpRole) error {
	iamClient, err := b.IAM(req.Storage)
	if err != nil {
		return fmt.Errorf(clientErrorTemplate, "IAM", err)
	}

	serviceAccountId, ok := req.Auth.Metadata["service_account_id"]
	if !ok {
		return errors.New("service account id metadata not associated with auth token, invalid")
	}

	serviceAccount, err := util.ServiceAccount(iamClient, serviceAccountId, role.ProjectId)
	if err != nil {
		return fmt.Errorf("cannot find service account %s", serviceAccountId)
	}

	if err := b.validateIAMServiceAccount(serviceAccount, role); err != nil {
		return errors.New("service account is no longer authorized for role")
	}

	return nil
}

// validateAgainstIAMRole returns an error if the given IAM service account is not authorized for the role.
func (b *GcpAuthBackend) validateIAMServiceAccount(serviceAccount *iam.ServiceAccount, role *gcpRole) error {
	// This is just in case - project should already be used to retrieve service account.
	if role.ProjectId != serviceAccount.ProjectId {
		return fmt.Errorf("service account %s does not belong to project %s", serviceAccount.Email, role.ProjectId)
	}

	// Check if role has the wildcard as the only service account.
	if len(role.ServiceAccounts) == 1 && role.ServiceAccounts[0] == serviceAccountsWildcard {
		return nil
	}

	// Check for service account id/email.
	if strutil.StrListContains(role.ServiceAccounts, serviceAccount.Email) ||
		strutil.StrListContains(role.ServiceAccounts, serviceAccount.UniqueId) {
		return nil
	}

	return fmt.Errorf("service account %s (id: %s) is not authorized for role",
		serviceAccount.Email, serviceAccount.UniqueId)
}

// ---- GCE login domain ----
// pathGceLogin attempts a login operation using the parsed login info.
func (b *GcpAuthBackend) pathGceLogin(req *logical.Request, loginInfo *gcpLoginInfo) (*logical.Response, error) {
	key, err := util.Oauth2RSAPublicKey(loginInfo.KeyId)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if err := loginInfo.validateJWT(key); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	gceClient, err := b.GCE(req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(clientErrorTemplate, "GCE", err)), nil
	}

	role := loginInfo.Role
	metadata := loginInfo.GceMetadata
	if metadata == nil {
		return logical.ErrorResponse("could not get GCE metadata from given JWT"), nil
	}

	if role.ProjectId != loginInfo.GceMetadata.ProjectId {
		return logical.ErrorResponse(fmt.Sprintf(
			"GCE instance must belong to project %s; metadata given has project %s",
			role.ProjectId, loginInfo.GceMetadata.ProjectId)), nil
	}

	// Verify instance exists.
	instance, err := gceClient.Instances.Get(metadata.ProjectId, metadata.Zone, metadata.InstanceName).Do()
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"error when attempting to find instance (project %s, zone: %s, instance: %s) :%v",
			metadata.ProjectId, metadata.Zone, metadata.InstanceName, err)), nil
	}

	if err := b.validateGCEInstance(instance, req.Storage, role, metadata.Zone, loginInfo.ServiceAccountId); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Period: role.Period,
			Persona: &logical.Persona{
				Name: fmt.Sprintf("gce-%s", strconv.FormatUint(instance.Id, 10)),
			},
			Policies: role.Policies,
			Metadata: map[string]string{
				"project_id":         metadata.ProjectId,
				"zone":               metadata.Zone,
				"instance_id":        metadata.InstanceId,
				"instance_name":      metadata.InstanceName,
				"service_account_id": loginInfo.ServiceAccountId,
				"role":               loginInfo.RoleName,
			},
			DisplayName: instance.Name,
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       role.TTL,
			},
		},
	}

	return resp, nil
}

// pathGceRenew returns an error if the instance referenced in the auth token metadata cannot renew the
// auth token for the given role.
func (b *GcpAuthBackend) pathGceRenew(req *logical.Request, role *gcpRole) error {
	gceClient, err := b.GCE(req.Storage)
	if err != nil {
		return fmt.Errorf(clientErrorTemplate, "GCE", err)
	}

	projectId, ok := req.Auth.Metadata["project_id"]
	if !ok {
		return errors.New("project_id metadata not associated with auth token, invalid")
	}
	zone, ok := req.Auth.Metadata["zone"]
	if !ok {
		return errors.New("zone metadata not associated with auth token, invalid")
	}
	instance_name, ok := req.Auth.Metadata["instance_name"]
	if !ok {
		return errors.New("instance_name metadata not associated with auth token, invalid")
	}
	serviceAccountId, ok := req.Auth.Metadata["service_account_id"]
	if !ok {
		return errors.New("service_account_id metadata not associated with auth token, invalid")
	}

	instance, err := gceClient.Instances.Get(projectId, zone, instance_name).Do()
	if err != nil {
		return fmt.Errorf("cannot find instance (project %s, zone: %s, instance: %s): %v", projectId, zone, instance_name, err)
	}

	if err := b.validateGCEInstance(instance, req.Storage, role, zone, serviceAccountId); err != nil {
		return err
	}

	return nil
}

// validateGCEInstance returns an error if the given GCE instance is not authorized for the role.
func (b *GcpAuthBackend) validateGCEInstance(
	instance *compute.Instance, s logical.Storage, role *gcpRole, zone, serviceAccountId string) error {
	gceClient, err := b.GCE(s)
	if err != nil {
		return err
	}

	// Verify instance is still running.
	if !util.IsValidInstanceStatus(instance.Status) {
		return fmt.Errorf("authenticating instance %s has invalid status '%s'",
			instance.Name, instance.Status)
	}

	if len(role.ServiceAccounts) > 0 {
		iamClient, err := b.IAM(s)
		if err != nil {
			return err
		}

		serviceAccount, err := util.ServiceAccount(iamClient, serviceAccountId, role.ProjectId)
		if err != nil {
			return fmt.Errorf("could not find service acocunt with id '%s': ")
		}

		if !(strutil.StrListContains(role.ServiceAccounts, serviceAccount.Email) ||
			strutil.StrListContains(role.ServiceAccounts, serviceAccount.UniqueId)) {
			return fmt.Errorf("GCE instance's service account email (%s) or id (%s) not found in role service accounts: %v",
				serviceAccount.Email, serviceAccount.UniqueId, role.ServiceAccounts)
		}
	}
	// Verify instance has role labels if labels were set on role.
	for k, expectedV := range role.Labels {
		actualV, ok := instance.Labels[k]
		if !ok || actualV != expectedV {
			return fmt.Errorf("role label '%s:%s' not found on GCE instance", k, expectedV)
		}
	}

	// Verify that instance is in zone or region if given.
	if len(role.Zone) > 0 {
		if zone != role.Zone {
			return fmt.Errorf("instance is not in role zone '%s'", role.Zone)
		}
	} else if len(role.Region) > 0 {
		zone, err := gceClient.Zones.Get(role.ProjectId, zone).Do()
		if err != nil {
			return fmt.Errorf("could not verify instance zone '%s' is available for project '%s': %v", role.ProjectId, zone, err)
		}
		if zone.Region != role.Region {
			return fmt.Errorf("zone '%s' is not in region '%s'", zone.Name, zone.Region)
		}
	}

	// If instance group is given, verify group exists and that instance is in group.
	if len(role.InstanceGroup) > 0 {
		var group *compute.InstanceGroup
		var err error

		// Check if group should be zonal or regional.
		if len(role.Zone) > 0 {
			group, err = gceClient.InstanceGroups.Get(role.ProjectId, role.Zone, role.InstanceGroup).Do()
			if err != nil {
				return fmt.Errorf("could not find role instance group %s (project %s, zone %s)", role.InstanceGroup, role.ProjectId, role.Zone)
			}
		} else if len(role.Region) > 0 {
			group, err = gceClient.RegionInstanceGroups.Get(role.ProjectId, role.Region, role.InstanceGroup).Do()
			if err != nil {
				return fmt.Errorf("could not find role instance group %s (project %s, region %s)", role.InstanceGroup, role.ProjectId, role.Region)
			}
		} else {
			return errors.New("expected zone or region to be set for GCE role '%s' with instance group")
		}

		// Verify instance group contains authenticating instance.
		instanceIdFilter := fmt.Sprintf("%s eq %s", "id", instance.Id)
		listInstanceReq := &compute.InstanceGroupsListInstancesRequest{}
		_, err = gceClient.InstanceGroups.ListInstances(role.ProjectId, role.Zone, group.Name, listInstanceReq).Filter(instanceIdFilter).Do()
		if err != nil {
			return fmt.Errorf("instance %s is not part of role instance group %s", instance.Name, role.InstanceGroup)
		}
	}

	return nil
}

const pathLoginHelpSyn = `Authenticates Google Cloud Platform entities with Vault.`
const pathLoginHelpDesc = `
Authenticate Google Cloud Platform (GCP) entities.

Currently supports authentication for:

IAM service accounts
=====================
IAM service accounts can use GCP APIs or tools to sign a JSON Web Token (JWT).
This JWT should contain the id (expected field 'client_id') or email
(expected field 'client_email') of the authenticating service account in its claims.
Vault verifies the signed JWT and parses the identity of the account.

Renewal is rejected if the role, service account, or original signing key no longer exists.
`
