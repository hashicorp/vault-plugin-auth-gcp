package gcpauth

import (
	"fmt"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRoleIam(t *testing.T) {
	b := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(t)
	}

	serviceAccounts := []string{creds.ClientEmail}
	roleName := "testrole"
	dataCreate := map[string]interface{}{
		"name":             roleName,
		"type":             "iam",
		"project_id":       creds.ProjectId,
		"service_accounts": strings.Join(serviceAccounts, ","),
	}
	expectedCreate := map[string]interface{}{
		"name":             roleName,
		"role_type":        "iam",
		"project_name":     os.Getenv("GOOGLE_PROJECT"),
		"service_accounts": serviceAccounts,
	}

	serviceAccounts = []string{creds.ClientEmail, "testaccount@google.com"}
	dataUpdate := map[string]interface{}{
		"policies":         "dev",
		"ttl":              1000,
		"max_ttl":          2000,
		"period":           30,
		"service_accounts": strings.Join(serviceAccounts, ","),
	}
	expectedUpdate := map[string]interface{}{
		"role_type":                "iam",
		"project_name":             os.Getenv("GOOGLE_PROJECT"),
		"policies":                 []string{"dev", "default"},
		"disable_reauthentication": false,
		"ttl":              time.Duration(1000),
		"max_ttl":          time.Duration(2000),
		"period":           time.Duration(30),
		"service_accounts": serviceAccounts,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		AcceptanceTest: true,
		PreCheck:       func() { testAccPreCheck(t) },
		Backend:        b,
		Steps: []logicaltest.TestStep{
			testRoleCreate(t, roleName, dataCreate),
			testRoleRead(t, roleName, expectedCreate),
			testRoleUpdate(t, roleName, dataUpdate),
			testRoleRead(t, roleName, expectedUpdate),
		},
	})
}

func testRoleCreate(t *testing.T, roleName string, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Data:      d,
	}
}

func testRoleUpdate(t *testing.T, roleName string, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Data:      d,
	}
}

func testRoleRead(t *testing.T, roleName string, expected map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Check: func(resp *logical.Response) error {
			if resp.IsError() {
				return resp.Error()
			}

			if err := testBaseRoleRead(resp, expected); err != nil {
				return err
			}

			if !strutil.EquivalentSlices(resp.Data["service_accounts"].([]string), expected["service_accounts"].([]string)) {
				return fmt.Errorf("service_accounts mismatch, expected %v but got %v", expected["service_accounts"], resp.Data["service_accounts"])
			}

			return nil
		},
	}
}

func testBaseRoleRead(resp *logical.Response, expected map[string]interface{}) error {
	if resp.Data["role_type"] != expected["role_type"] {
		return fmt.Errorf("role_type mismatch, expected %s but got %s", expected["role_type"], resp.Data["role_type"])
	}

	if resp.Data["project_id"] != expected["project_id"] {
		fmt.Errorf("project_id mismatch, expected %s but got %s", expected["disable_tidy"], resp.Data["disable_tidy"])
	}

	expectedVal, ok := expected["policies"]
	if !ok {
		expectedVal = []string{"default"}
	}
	if !policyutil.EquivalentPolicies(resp.Data["policies"].([]string), expectedVal.([]string)) {
		return fmt.Errorf("policies mismatch, expected %v but got %v", expectedVal, resp.Data["policies"])
	}

	expectedVal, ok = expected["disable_reauthentication"]
	if !ok {
		expectedVal = false
	}
	if resp.Data["disable_reauthentication"] != expectedVal {
		return fmt.Errorf("disable_reauthentication mismatch, expected %s but got %s", expected["disable_reauthentication"], resp.Data["disable_reauthentication"])
	}

	expectedVal, ok = expected["ttl"]
	if !ok {
		expectedVal = time.Duration(0)
	}
	if resp.Data["ttl"] != expectedVal {
		return fmt.Errorf("ttl mismatch, expected %s but got %s", expectedVal, resp.Data["ttl"])
	}

	expectedVal, ok = expected["max_ttl"]
	if !ok {
		expectedVal = time.Duration(0)
	}
	if resp.Data["max_ttl"] != expectedVal {
		return fmt.Errorf("max_ttl mismatch, expected %s but got %s", expectedVal, resp.Data["max_ttl"])
	}

	expectedVal, ok = expected["period"]
	if !ok {
		expectedVal = time.Duration(0)
	}
	if resp.Data["period"] != expectedVal {
		return fmt.Errorf("period mismatch, expected %s but got %s", expectedVal, resp.Data["period"])
	}
	return nil
}
