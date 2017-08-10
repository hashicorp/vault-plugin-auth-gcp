package gcpauth

import (
	"errors"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/hashicorp/vault-plugin-auth-gcp/util"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"google.golang.org/api/iam/v1"
	"time"
)

const (
	loginPath string = "login"

	// Default duration that JWT tokens must expire within to be accepted
	defaultJwtExpMin int = 15

	clientErrorTemplate string = "backend not configured properly, could not create %s client: %s"
)

func pathLogin(b *GcpAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s$", loginPath),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. Required.`,
			},
			"kid": {
				Type:        framework.TypeString,
				Description: `The ID of the service account key used to sign the request. If not specified, Vault will attempt to infer this from a 'kid' value in the JWT header.`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT for authenticating a service account.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *GcpAuthBackend) pathLogin(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role is required"), nil
	}
	role, err := b.role(req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' not found", roleName)), nil
	}

	loginInfo, err := b.parseLoginInfo(data)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to parse login info from given data: %s", err)), nil
	}

	switch role.RoleType {
	case iamRoleType:
		return b.pathIamLogin(req, loginInfo, roleName, role)
	default:
		return logical.ErrorResponse(fmt.Sprintf("login against role type '%s' is unsupported", role.RoleType)), nil
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
	// ID or email of an IAM service account or that inferred for a GCE VM.
	serviceAccountId string

	// ID or email of an IAM service account or that inferred for a GCE VM.
	instanceId string

	// ID of the public key to verify the signed JWT.
	keyId string

	// Signed JWT
	JWT jwt.JWT
}

func (b *GcpAuthBackend) parseLoginInfo(data *framework.FieldData) (*gcpLoginInfo, error) {
	loginInfo := &gcpLoginInfo{}
	var err error

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
		loginInfo.keyId = jwsVal.Protected().Get("kid").(string)
	} else {
		loginInfo.keyId = data.Get("kid").(string)
	}
	if loginInfo.keyId == "" {
		return nil, errors.New("either kid must be provided or JWT must have 'kid' header value")
	}

	// Parse claims
	loginInfo.JWT, err = jws.ParseJWT(signedJwtBytes)
	if err != nil {
		return nil, err
	}

	sub, ok := loginInfo.JWT.Claims().Subject()
	if !ok {
		return nil, errors.New("expected 'sub' claim with service account id or email")
	}
	loginInfo.serviceAccountId = sub

	return loginInfo, nil
}

func (info *gcpLoginInfo) validateJWT(req *logical.Request, keyPEM string, maxJwtExp time.Duration) error {
	pubKey, err := util.PublicKey(keyPEM)
	if err != nil {
		return err
	}

	validator := &jwt.Validator{
		Expected: jwt.Claims{
			"aud": fmt.Sprintf(req.MountPoint + loginPath),
		},
		Fn: func(c jwt.Claims) error {
			exp, ok := c.Expiration()
			if !ok {
				return errors.New("JWT claim 'exp' is required")
			}
			delta := exp.Sub(time.Now())
			if delta > maxJwtExp {
				return fmt.Errorf("JWT expires in %v minutes but must expire within %v for this role. Please generate a new token with a valid expiration.",
					int(delta/time.Minute), maxJwtExp)
			}

			return nil
		},
	}

	if err := info.JWT.Validate(pubKey, crypto.SigningMethodRS256, validator); err != nil {
		return fmt.Errorf("invalid JWT: %s", err)
	}

	return nil
}

// ---- IAM login domain ----

func (b *GcpAuthBackend) pathIamLogin(req *logical.Request, loginInfo *gcpLoginInfo, roleName string, role *gcpRole) (*logical.Response, error) {
	iamClient, err := b.IAM(req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(clientErrorTemplate, "IAM", err)), nil
	}

	// Verify and get service account from signed JWT.
	key, err := util.ServiceAccountKey(iamClient, loginInfo.keyId, loginInfo.serviceAccountId, role.ProjectId)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("service account %s has no key with id %s", loginInfo.serviceAccountId, loginInfo.keyId)), nil
	}

	if err := loginInfo.validateJWT(req, key.PublicKeyData, role.MaxJwtExp); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	serviceAccount, err := util.ServiceAccount(iamClient, loginInfo.serviceAccountId, role.ProjectId)
	if err != nil {
		return nil, err
	}
	if serviceAccount == nil {
		return nil, errors.New("service account is empty")
	}

	// Validate service account can login against role.
	if err := b.validateAgainstIAMRole(serviceAccount, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Period:   role.Period,
			Policies: role.Policies,
			Metadata: map[string]string{
				"service_account_id":    serviceAccount.UniqueId,
				"service_account_email": serviceAccount.Email,
				"role":                  roleName,
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

	if err := b.validateAgainstIAMRole(serviceAccount, role); err != nil {
		return errors.New("service account is no longer authorized for role")
	}

	return nil
}

// validateAgainstIAMRole returns an error if the given IAM service account is not authorized for the role.
func (b *GcpAuthBackend) validateAgainstIAMRole(serviceAccount *iam.ServiceAccount, role *gcpRole) error {
	if strutil.StrListContains(role.ServiceAccounts, serviceAccount.Email) ||
		strutil.StrListContains(role.ServiceAccounts, serviceAccount.UniqueId) {
		return nil
	}

	return fmt.Errorf("service account %s (id: %s) is not authorized for role",
		serviceAccount.Email, serviceAccount.UniqueId)
}

const pathLoginHelpSyn = `Authenticates Google Cloud Platform entities with Vault.`
const pathLoginHelpDesc = `
Authenticate Google Cloud Platform (GCP) entities.

Currently supports authentication for:

IAM service accounts
=====================
IAM service accounts can use GCP APIs or tools to sign a JSON Web Token (JWT).
This JWT should contain the id (expected field 'client_id') or email
(expected field 'client_email') of the authenticationg service account in its claims.
Vault verifies the signed JWT and parses the identity of the account.

Renewal is rejected if the role, service account, or original signing key no longer exists.
`
