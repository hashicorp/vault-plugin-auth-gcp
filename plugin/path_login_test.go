package gcpauth

import (
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/hashicorp/vault-plugin-auth-gcp/util"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"google.golang.org/api/iam/v1"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	googleCredentialsEnv = "GOOGLE_CREDENTIALS"
	testMountPoint       = "auth/testgcp"
)

func TestLoginIam(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": os.Getenv(googleCredentialsEnv),
	})

	roleName := "testrole"
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":             roleName,
		"type":             "iam",
		"policies":         "dev, prod",
		"project_id":       creds.ProjectId,
		"service_accounts": creds.ClientEmail,
		"ttl":              1800,
		"max_ttl":          1800,
	})

	jwtVal := getTestIamToken(t, creds, time.Now().Add(time.Duration(defaultJwtExpMin-5)*time.Minute))
	loginData := map[string]interface{}{
		"role": roleName,
		"jwt":  jwtVal,
	}

	metadata := map[string]string{
		"service_account_id":    creds.ClientId,
		"service_account_email": creds.ClientEmail,
		"role":                  roleName,
	}
	role := &gcpRole{
		RoleType:        "iam",
		ProjectId:       creds.ProjectId,
		Policies:        []string{"default", "dev", "prod"},
		TTL:             time.Duration(1800) * time.Second,
		MaxTTL:          time.Duration(1800) * time.Second,
		Period:          time.Duration(0),
		ServiceAccounts: []string{creds.ClientEmail},
	}
	testLoginIam(t, b, reqStorage, loginData, metadata, role)
}

// TestLoginIam_UnauthorizedRole checks that we return an error response
// if the user attempts to login against a role it is not authorized for.
func TestLoginIam_UnauthorizedRole(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	roleName := "testrolenologin"

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": os.Getenv(googleCredentialsEnv),
	})
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"type":             "iam",
		"name":             roleName,
		"project_id":       creds.ProjectId,
		"service_accounts": "notarealserviceaccount",
	})

	jwtVal := getTestIamToken(t, creds, time.Now().Add(time.Duration(defaultJwtExpMin-5)*time.Minute))
	loginData := map[string]interface{}{
		"role": roleName,
		"jwt":  jwtVal,
	}

	testLoginError(t, b, reqStorage, loginData, []string{
		"service account",
		creds.ClientEmail,
		creds.ClientId,
		"is not authorized for role",
	})
}

// TestLoginIam_MissingRole checks that we return an error response if role is not provided.
func TestLoginIam_MissingRole(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	roleName := "doesnotexist"

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": os.Getenv(googleCredentialsEnv),
	})
	jwtVal := getTestIamToken(t, creds, time.Now().Add(time.Duration(defaultJwtExpMin-5)*time.Minute))
	loginData := map[string]interface{}{
		"jwt": jwtVal,
	}
	testLoginError(t, b, reqStorage, loginData, []string{"role is required"})

	loginData["role"] = roleName
	testLoginError(t, b, reqStorage, loginData, []string{roleName, "not found"})
}

// TestLoginIam_ExpiredJwt checks that we return an error response for an expired JWT.
func TestLoginIam_ExpiredJwt(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	roleName := "testrole"
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":             roleName,
		"type":             "iam",
		"policies":         "dev, prod",
		"project_id":       creds.ProjectId,
		"service_accounts": creds.ClientEmail,
	})

	// Create fake self-signed JWT to test.
	claims := jws.Claims{}
	claims.SetAudience(testMountPoint + loginPath)
	claims.SetSubject(creds.ClientId)
	claims.SetExpiration(time.Now().Add(-100 * time.Second))

	privateKey, err := crypto.ParseRSAPrivateKeyFromPEM([]byte(creds.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	jwtVal, err := jws.NewJWT(claims, crypto.SigningMethodRS256).Serialize(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	loginData := map[string]interface{}{
		"role": roleName,
		"kid":  creds.PrivateKeyId,
		"jwt":  jwtVal,
	}

	testLoginError(t, b, reqStorage, loginData, []string{
		"invalid JWT",
		"token is expired",
	})
}

// TestLoginIam_JwtExpiresLate checks that we return an error response for an expired JWT.
func TestLoginIam_JwtExpiresTime(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	roleName := "testrole"

	maxJwtExpSeconds := 2400
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":             roleName,
		"type":             "iam",
		"policies":         "dev, prod",
		"project_id":       creds.ProjectId,
		"service_accounts": creds.ClientEmail,
		"max_jwt_exp":      maxJwtExpSeconds,
	})

	badExp := time.Now().Add(time.Duration(maxJwtExpSeconds+1200) * time.Second)
	loginData := map[string]interface{}{
		"role": roleName,
		"jwt":  getTestIamToken(t, creds, badExp),
	}

	testLoginError(t, b, reqStorage, loginData, []string{
		"invalid JWT",
		fmt.Sprintf("expire within %v", time.Duration(maxJwtExpSeconds)*time.Second),
	})

	validExp := time.Now().Add(time.Duration(maxJwtExpSeconds-1200) * time.Second)
	loginData["jwt"] = getTestIamToken(t, creds, validExp)

	metadata := map[string]string{
		"service_account_id":    creds.ClientId,
		"service_account_email": creds.ClientEmail,
		"role":                  roleName,
	}
	role := &gcpRole{
		RoleType:        "iam",
		ProjectId:       creds.ProjectId,
		Policies:        []string{"default", "dev", "prod"},
		ServiceAccounts: []string{creds.ClientEmail},
	}
	testLoginIam(t, b, reqStorage, loginData, metadata, role)

}

func testLoginIam(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, expectedMetadata map[string]string, role *gcpRole) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		MountPoint: testMountPoint,
		Data:       d,
		Storage:    s,
	})

	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if !policyutil.EquivalentPolicies(resp.Auth.Policies, role.Policies) {
		t.Fatalf("policy mismatch, expected %v but got %v", role.Policies, resp.Auth.Policies)
	}

	if resp.Auth.Period != role.Period {
		t.Fatalf("period mismatch, expected %v but got %v", role.Period, resp.Auth.Period)
	}

	// Check metadata
	for k, expected := range expectedMetadata {
		actual, ok := resp.Auth.Metadata[k]
		if !ok {
			t.Fatalf("metadata value '%s' not found, expected value '%s'", k, expected)
		}
		if actual != expected {
			t.Fatalf("metadata value '%s' mismatch, expected '%s' but got '%s'", k, expected, actual)
		}
	}

	// Check lease options
	if !resp.Auth.LeaseOptions.Renewable {
		t.Fatal("expected lease options to be renewable")
	}
	if resp.Auth.LeaseOptions.TTL != role.TTL {
		t.Fatalf("lease option TTL mismatch, expected %v but got %v", role.TTL, resp.Auth.LeaseOptions.TTL)
	}
}

func testLoginError(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, errorSubstrings []string) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		MountPoint: testMountPoint,
		Data:       d,
		Storage:    s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if !resp.IsError() {
		t.Fatal("expected error response")
	}

	errMsg := strings.ToLower(resp.Error().Error())
	for _, v := range errorSubstrings {
		if !strings.Contains(errMsg, strings.ToLower(v)) {
			t.Fatalf("expected '%s' to be in error: '%s'", v, resp.Error())
		}
	}
}

func getTestIamToken(t *testing.T, creds *util.GcpCredentials, exp time.Time) string {
	// Generate signed JWT to login with.
	httpClient, err := util.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}
	iamClient, err := iam.New(httpClient)
	if err != nil {
		t.Fatal(err)
	}

	expectedJwtAud := testMountPoint + loginPath
	signedJwtResp, err := util.ServiceAccountLoginJwt(iamClient, exp, expectedJwtAud, creds.ProjectId, creds.ClientEmail)
	if err != nil {
		t.Fatal(err)
	}

	return signedJwtResp.SignedJwt
}
