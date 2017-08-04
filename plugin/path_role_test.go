package gcpauth

import (
	"fmt"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"os"
	"strings"
	"testing"
)

func TestRoleIam(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(t)
	}

	serviceAccounts := []string{creds.ClientEmail}
	roleName := "testrole"
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":             roleName,
		"type":             "iam",
		"project_id":       creds.ProjectId,
		"service_accounts": strings.Join(serviceAccounts, ","),
	})
	testIamRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":             roleName,
		"role_type":        "iam",
		"project_name":     os.Getenv("GOOGLE_PROJECT"),
		"service_accounts": serviceAccounts,
	})

	serviceAccounts = []string{creds.ClientEmail, "testaccount@google.com"}
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":             roleName,
		"policies":         "dev",
		"ttl":              1000,
		"max_ttl":          2000,
		"period":           30,
		"max_jwt_exp":      1200, // 20 minutes
		"service_accounts": strings.Join(serviceAccounts, ","),
	})

	testIamRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"role_type":                "iam",
		"project_name":             os.Getenv("GOOGLE_PROJECT"),
		"policies":                 []string{"dev", "default"},
		"disable_reauthentication": false,
		"ttl":              1000,
		"max_ttl":          2000,
		"period":           30,
		"max_jwt_exp":      1200,
		"service_accounts": serviceAccounts,
	})
}

func TestRoleIam_ServiceAccounts(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(t)
	}

	stableAccounts := []string{"id1234", "test1@google.com"}
	toRemove := []string{"toremove12345", "toremove@google.com"}
	toAdd := []string{"toAdd34567", "toAdd@google.com"}

	roleName := "testrole"
	createAccounts := append(stableAccounts, toRemove...)
	dataCreate := map[string]interface{}{
		"name":             roleName,
		"type":             "iam",
		"project_id":       creds.ProjectId,
		"service_accounts": strings.Join(createAccounts, ","),
	}
	expectedCreate := map[string]interface{}{
		"name":             roleName,
		"role_type":        "iam",
		"project_name":     os.Getenv("GOOGLE_PROJECT"),
		"service_accounts": createAccounts,
	}

	dataUpdate := map[string]interface{}{
		"name":   roleName,
		"add":    strings.Join(toAdd, ","),
		"remove": strings.Join(toRemove, ","),
	}
	expectedRead := map[string]interface{}{
		"name":             roleName,
		"role_type":        "iam",
		"project_name":     os.Getenv("GOOGLE_PROJECT"),
		"service_accounts": append(stableAccounts, toAdd...),
	}

	testRoleCreate(t, b, reqStorage, dataCreate)
	testIamRoleRead(t, b, reqStorage, roleName, expectedCreate)
	testRoleUpdateServiceAccounts(t, b, reqStorage, dataUpdate)
	testIamRoleRead(t, b, reqStorage, roleName, expectedRead)
}

func testRoleCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleUpdateServiceAccounts(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s/service-accounts", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testIamRoleRead(t *testing.T, b logical.Backend, s logical.Storage, roleName string, expected map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if err := testBaseRoleRead(resp, expected); err != nil {
		t.Fatal(err)
	}

	if !strutil.EquivalentSlices(resp.Data["service_accounts"].([]string), expected["service_accounts"].([]string)) {
		t.Fatalf("service_accounts mismatch, expected %v but got %v", expected["service_accounts"], resp.Data["service_accounts"])
	}
}

func testBaseRoleRead(resp *logical.Response, expected map[string]interface{}) error {
	expectedVal, ok := expected["role_type"]
	if ok && resp.Data["role_type"].(string) != expectedVal.(string) {
		return fmt.Errorf("role_type mismatch, expected %s but got %s", expectedVal, resp.Data["role_type"])
	}

	expectedVal, ok = expected["project_id"]
	if ok && resp.Data["project_id"].(string) != expectedVal.(string) {
		return fmt.Errorf("project_id mismatch, expected %s but got %s", expectedVal, resp.Data["project_id"])
	}

	expectedVal, ok = expected["policies"]
	if !ok {
		expectedVal = []string{"default"}
	}
	if !policyutil.EquivalentPolicies(resp.Data["policies"].([]string), expectedVal.([]string)) {
		return fmt.Errorf("policies mismatch, expected %v but got %v", expectedVal, resp.Data["policies"])
	}

	expectedVal, ok = expected["max_jwt_exp"]
	if !ok {
		expectedVal = int(defaultJwtExpMin * 60)
	}
	if resp.Data["max_jwt_exp"] != expectedVal {
		return fmt.Errorf("max_jwt_exp mismatch, expected %d but got %d", expectedVal, resp.Data["max_jwt_exp"])
	}

	expectedVal, ok = expected["ttl"]
	if !ok {
		expectedVal = 0
	}
	if resp.Data["ttl"] != expectedVal {
		return fmt.Errorf("ttl mismatch, expected %d but got %d", expectedVal, resp.Data["ttl"])
	}

	expectedVal, ok = expected["max_ttl"]
	if !ok {
		expectedVal = 0
	}
	if resp.Data["max_ttl"] != expectedVal {
		return fmt.Errorf("max_ttl mismatch, expected %d but got %d", expectedVal, resp.Data["max_ttl"])
	}

	expectedVal, ok = expected["period"]
	if !ok {
		expectedVal = 0
	}
	if resp.Data["period"] != expectedVal {
		return fmt.Errorf("period mismatch, expected %d but got %d", expectedVal, resp.Data["period"])
	}
	return nil
}
