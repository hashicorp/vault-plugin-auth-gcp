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
	expectedJwtAud string = "auth/gcp/login"
)

func pathLogin(b *GcpAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. Required.`,
			},
			"key_id": {
				Type:        framework.TypeString,
				Description: `The ID of the service account key used to sign the request. If not specified, Vault will attempt to infer this from a 'kid' value in the JWT header.`,
			},
			"signed_jwt": {
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
	if err := b.initClients(req.Storage); err != nil {
		return logical.ErrorResponse("Unable to initialize GCP backend: " + err.Error()), nil
	}

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

	switch role.RoleType {
	case iamRoleType:
		return b.pathIamLogin(req, data, role)
	default:
		return logical.ErrorResponse(fmt.Sprintf("login against role type '%s' is unsupported", role.RoleType)), nil
	}
}

func (b *GcpAuthBackend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.initClients(req.Storage); err != nil {
		return logical.ErrorResponse("Unable to initialize GCP backend: " + err.Error()), nil
	}

	// Check role exists and allowed policies are still the same.
	roleName, ok := req.Auth.Metadata["role"]
	if !ok {
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
	if role.Period > time.Duration(0) {
		// Replenish the TTL with current role's Period.
		req.Auth.TTL = role.Period
		return &logical.Response{Auth: req.Auth}, nil
	} else {
		return framework.LeaseExtend(role.TTL, role.MaxTTL, b.System())(req, data)
	}
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

// ---- IAM login domain ----

// iamLoginInfo represents the data given to Vault for logging in using the IAM method.1
type iamLoginInfo struct {
	// ID or email of the service account.
	serviceAccountId string

	// ID of the public key to verify the signed JWT.
	keyId string

	// Method used to sign the JWT.
	signingMethod crypto.SigningMethod

	// Signed JWT
	JWT jwt.JWT
}

func (b *GcpAuthBackend) pathIamLogin(req *logical.Request, data *framework.FieldData, role *gcpRole) (*logical.Response, error) {
	loginInfo, err := b.parseIamLoginInfo(data)
	if err != nil {
		return logical.ErrorResponse(
			fmt.Sprintf("unable to parse input for login against role type '%s': %s", role.RoleType, err)), nil
	}

	// Verify and get service account from signed JWT.
	serviceAccount, err := b.verifiedServiceAccount(loginInfo, role)
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
				"role":                  data.Get("role").(string),
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
	serviceAccountId, ok := req.Auth.Metadata["service_account_id"]
	if !ok {
		return errors.New("service account id metadata not associated with auth token, invalid")
	}

	serviceAccount, err := util.ServiceAccount(b.iamClient, serviceAccountId, role.ProjectId)
	if err != nil {
		return fmt.Errorf("cannot find service account %s", serviceAccountId)
	}

	if err := b.validateAgainstIAMRole(serviceAccount, role); err != nil {
		return errors.New("service account is no longer authorized for role")
	}

	return nil
}

func (b *GcpAuthBackend) parseIamLoginInfo(data *framework.FieldData) (*iamLoginInfo, error) {
	loginInfo := &iamLoginInfo{}
	var err error

	signedJwt, ok := data.GetOk("signed_jwt")
	if !ok {
		return nil, errors.New("signed_jwt argument is required")
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
		loginInfo.keyId = data.Get("key_id").(string)
	}
	if loginInfo.keyId == "" {
		return nil, errors.New("either keyId or 'kid' header value in signedJwt must be provided")
	}

	if headerVal.Has("alg") {
		loginInfo.signingMethod = jws.GetSigningMethod(headerVal.Get("alg").(string))
	} else {
		// Default to RSA256
		loginInfo.signingMethod = crypto.SigningMethodRS256
	}

	// Parse claims
	loginInfo.JWT, err = jws.ParseJWT(signedJwtBytes)
	if err != nil {
		return nil, err
	}
	sub, ok := loginInfo.JWT.Claims().Subject()
	if !ok {
		return nil, errors.New("signed jwt must have 'sub' claim with service account id or email")
	}
	loginInfo.serviceAccountId = sub
	return loginInfo, nil
}

// verifiedServiceAccount verifies login info and fetches the authenticating service account.
func (b *GcpAuthBackend) verifiedServiceAccount(loginInfo *iamLoginInfo, role *gcpRole) (*iam.ServiceAccount, error) {
	key, err := util.ServiceAccountKey(b.iamClient, loginInfo.keyId, loginInfo.serviceAccountId, role.ProjectId)
	if err != nil {
		return nil, err
	}

	pubKey, err := util.PublicKey(key.PublicKeyData)
	if err != nil {
		return nil, fmt.Errorf("could not get valid public key: %s", err)
	}
	jwtValidator := &jwt.Validator{
		Expected: jwt.Claims{
			"sub": loginInfo.serviceAccountId,
			"aud": expectedJwtAud,
		},
	}
	if err = loginInfo.JWT.Validate(pubKey, loginInfo.signingMethod, jwtValidator); err != nil {
		return nil, fmt.Errorf("invalid service account JWT: %s", err)
	}

	return util.ServiceAccount(b.iamClient, loginInfo.serviceAccountId, role.ProjectId)
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
