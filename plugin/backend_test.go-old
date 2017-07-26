package gcpauth

import (
	"errors"
	"fmt"
	"github.com/hashicorp/vault-plugin-auth-gcp/util"
	"github.com/hashicorp/vault/helper/logformat"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"github.com/mgutz/logxi/v1"
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

func TestBackend_LoginIam(t *testing.T) {
	b := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}
	configData := map[string]interface{}{
		"credentials": os.Getenv(googleCredentialsEnv),
	}

	roleData := map[string]interface{}{
		"type":             "iam",
		"policies":         "dev, prod",
		"project_id":       creds.ProjectId,
		"service_accounts": creds.ClientEmail,
		"ttl":              1800,
		"max_ttl":          1800,
	}
	expectedRole := &gcpRole{
		RoleType:                "iam",
		ProjectId:               creds.ProjectId,
		Policies:                []string{"default", "dev", "prod"},
		DisableReauthentication: false,
		TTL:             time.Duration(1800) * time.Second,
		MaxTTL:          time.Duration(1800) * time.Second,
		Period:          time.Duration(0),
		ServiceAccounts: []string{creds.ClientEmail},
	}

	roleDataNoLogin := map[string]interface{}{
		"type":             "iam",
		"project_id":       creds.ProjectId,
		"service_accounts": "notarealserviceaccount",
	}

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

	logicaltest.Test(t, logicaltest.TestCase{
		AcceptanceTest: true,
		PreCheck:       func() { testAccPreCheck(t) },
		Backend:        b,
		Steps: []logicaltest.TestStep{
			testConfigCreate(t, configData),
			testRoleCreate(t, defaultRoleName, roleData),
			testRoleCreate(t, defaultRoleNameNoLogin, roleDataNoLogin),
			testLoginIam(t, loginData, creds, expectedRole),
			testLoginError(t, loginData),
		},
	})
}

func testLoginIam(t *testing.T, d map[string]interface{}, loggedInUser *util.GcpCredentials, role *gcpRole) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      d,
		Check: func(resp *logical.Response) error {
			if resp.IsError() {
				return resp.Error()
			}

			if !policyutil.EquivalentPolicies(resp.Auth.Policies, role.Policies) {
				return fmt.Errorf("policy mismatch, expected %v but got %v", role.Policies, resp.Auth.Policies)
			}

			if resp.Auth.Period != role.Period {
				return fmt.Errorf("period mismatch, expected %v but got %v", role.Period, resp.Auth.Period)
			}

			// Check metadata
			if resp.Auth.Metadata["service_account_id"] != loggedInUser.ClientId {
				return fmt.Errorf("metadata mismatch, expected service_account_id %v but got %v", loggedInUser.ClientId, resp.Auth.Metadata["service_account_id"])
			}
			if resp.Auth.Metadata["service_account_email"] != loggedInUser.ClientEmail {
				return fmt.Errorf("metadata mismatch, expected service_account_email %v but got %v", loggedInUser.ClientEmail, resp.Auth.Metadata["service_account_email"])
			}
			if resp.Auth.Metadata["role"] != defaultRoleName {
				return fmt.Errorf("metadata mismatch, expected role %v but got %v", loggedInUser.ClientEmail, resp.Auth.Metadata["service_account_email"])
			}

			// Check lease options
			if !resp.Auth.LeaseOptions.Renewable {
				return errors.New("expected lease options to be renewable")
			}
			if resp.Auth.LeaseOptions.TTL != role.TTL {
				return fmt.Errorf("Lease option TTL mismatch, expected %v but got %v", role.TTL, resp.Auth.LeaseOptions.TTL)
			}
			return nil
		},
	}
}

func testLoginError(t *testing.T, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("login"),
		Data:      d,
		ErrorOk:   true,
		Check: func(resp *logical.Response) error {
			if !resp.IsError() {
				return fmt.Errorf("expected error, got response with auth %v", resp.Auth)
			}
			return nil
		},
	}
}

func getTestBackend(t *testing.T) logical.Backend {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := Backend()
	err := b.Setup(&logical.BackendConfig{
		Logger: logformat.NewVaultLogger(log.LevelTrace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	})
	if err != nil {
		t.Fatalf("Unable to create backend: %s", err)
	}

	return b
}

func testAccPreCheck(t *testing.T) {
	if _, err := getTestCredentials(); err != nil {
		t.Fatal(err)
	}
}

func getTestCredentials() (*util.GcpCredentials, error) {
	credentialsJSON := os.Getenv(googleCredentialsEnv)
	if credentialsJSON == "" {
		return nil, fmt.Errorf("%s must be set to JSON string of valid Google credentials file", googleCredentialsEnv)
	}

	credentials, err := util.Credentials(credentialsJSON)
	if err != nil {
		return nil, fmt.Errorf("Valid Google credentials JSON could not be read from %s env variable: %s", googleCredentialsEnv, err)
	}
	return credentials, nil
}
