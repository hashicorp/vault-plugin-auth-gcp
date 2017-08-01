package gcpauth

import (
	"github.com/hashicorp/vault-plugin-auth-gcp/util"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"google.golang.org/api/iam/v1"
	"os"
	"testing"
	"time"
)

const (
	googleCredentialsEnv = "GOOGLE_CREDENTIALS"

	defaultRoleName        = "testrole"
	defaultRoleNameNoLogin = "logindeniedrole"
)

func TestLoginIam(t *testing.T) {
	testAccPreCheck(t)
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	// Generate signed JWT to login with.
	httpClient, err := util.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}
	iamClient, err := iam.New(httpClient)
	if err != nil {
		t.Fatal(err)
	}
	signedJwtResp, err := util.ServiceAccountLoginJwt(iamClient, expectedJwtAud, creds.ProjectId, creds.ClientEmail)
	if err != nil {
		t.Fatal(err)
	}
	loginData := map[string]interface{}{
		"role":       defaultRoleName,
		"signed_jwt": signedJwtResp.SignedJwt,
	}

	// Create initial config.
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": os.Getenv(googleCredentialsEnv),
	})

	// Check login against role that user is allowed to login against.
	roleData := map[string]interface{}{
		"name":             defaultRoleName,
		"type":             "iam",
		"policies":         "dev, prod",
		"project_id":       creds.ProjectId,
		"service_accounts": creds.ClientEmail,
		"ttl":              1800,
		"max_ttl":          1800,
	}
	testRoleCreate(t, b, reqStorage, roleData)
	expectedRole := &gcpRole{
		RoleType:        "iam",
		ProjectId:       creds.ProjectId,
		Policies:        []string{"default", "dev", "prod"},
		TTL:             time.Duration(1800) * time.Second,
		MaxTTL:          time.Duration(1800) * time.Second,
		Period:          time.Duration(0),
		ServiceAccounts: []string{creds.ClientEmail},
	}
	testLoginIam(t, b, reqStorage, loginData, creds, expectedRole)

	// Test against initial role that user should not be allowed to login against.
	roleDataNoLogin := map[string]interface{}{
		"type":             "iam",
		"name":             defaultRoleNameNoLogin,
		"project_id":       creds.ProjectId,
		"service_accounts": "notarealserviceaccount",
	}
	testRoleCreate(t, b, reqStorage, roleDataNoLogin)

	loginData["role"] = defaultRoleNameNoLogin
	testLoginError(t, b, reqStorage, loginData)
}

func testLoginIam(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, loggedInUser util.GcpCredentials, role *gcpRole) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      d,
		Storage:   s,
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
	if resp.Auth.Metadata["service_account_id"] != loggedInUser.ClientId {
		t.Fatalf("metadata mismatch, expected service_account_id %v but got %v", loggedInUser.ClientId, resp.Auth.Metadata["service_account_id"])
	}
	if resp.Auth.Metadata["service_account_email"] != loggedInUser.ClientEmail {
		t.Fatalf("metadata mismatch, expected service_account_email %v but got %v", loggedInUser.ClientEmail, resp.Auth.Metadata["service_account_email"])
	}
	if resp.Auth.Metadata["role"] != defaultRoleName {
		t.Fatalf("metadata mismatch, expected role %v but got %v", loggedInUser.ClientEmail, resp.Auth.Metadata["service_account_email"])
	}

	// Check lease options
	if !resp.Auth.LeaseOptions.Renewable {
		t.Fatal("expected lease options to be renewable")
	}
	if resp.Auth.LeaseOptions.TTL != role.TTL {
		t.Fatal("Lease option TTL mismatch, expected %v but got %v", role.TTL, resp.Auth.LeaseOptions.TTL)
	}
}

func testLoginError(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response")
	}
}
