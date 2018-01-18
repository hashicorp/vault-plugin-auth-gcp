package gcpauth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"reflect"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
)

const (
	defaultRoleName = "testrole"
	defaultProject  = "project-123456"
)

// Defaults for verifying response data. If a value is not included here, it must be included in the
// 'expected' map param for a test.
var expectedDefaults map[string]interface{} = map[string]interface{}{
	"policies":               []string{},
	"ttl":                    int64(baseRoleFieldSchema["ttl"].Default.(int)),
	"max_ttl":                int64(baseRoleFieldSchema["ttl"].Default.(int)),
	"period":                 int64(baseRoleFieldSchema["ttl"].Default.(int)),
	"bound_service_accounts": []string{},
	// IAM
	"max_jwt_exp":         int64(iamOnlyFieldSchema["max_jwt_exp"].Default.(int)),
	"allow_gce_inference": iamOnlyFieldSchema["allow_gce_inference"].Default.(bool),
	// GCE
	"bound_zone":           "",
	"bound_region":         "",
	"bound_instance_group": "",
	"bound_labels":         "",
}

//-- IAM ROLE TESTS --
func TestRoleUpdateIam(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	serviceAccounts := []string{"dev1@project-123456.iam.gserviceaccounts.com", "aserviceaccountid"}

	// Bare minimum for iam roles
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"type":                   iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})
	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"name":                   defaultRoleName,
		"role_type":              iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": serviceAccounts,
	})

	serviceAccounts = append(serviceAccounts, "testaccount@google.com")
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"policies":               "dev",
		"ttl":                    1000,
		"max_ttl":                2000,
		"period":                 30,
		"max_jwt_exp":            20 * 60, // 20 minutes
		"allow_gce_inference":    false,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"role_type":              iamRoleType,
		"project_id":             defaultProject,
		"policies":               []string{"dev"},
		"ttl":                    int64(1000),
		"max_ttl":                int64(2000),
		"period":                 int64(30),
		"max_jwt_exp":            int64(20 * 60),
		"allow_gce_inference":    false,
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleIam_Wildcard(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	defaultRoleName := "testrole"
	serviceAccounts := []string{"*", "dev1@project-123456.iam.gserviceaccounts.com", "aserviceaccountid"}

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"type":                   iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	}, []string{
		fmt.Sprintf("cannot provide IAM service account wildcard '%s' (for all service accounts) with other service accounts", serviceAccountsWildcard),
	})

	serviceAccounts = []string{"*"}
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"type":                   iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"role_type":              iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleIam_EditServiceAccounts(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	initial := []string{"id1234", "test1@google.com"}
	data := map[string]interface{}{
		"name":                   defaultRoleName,
		"type":                   iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": strings.Join(initial, ","),
	}
	expectedRole := map[string]interface{}{
		"name":                   defaultRoleName,
		"role_type":              iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": initial,
	}

	testRoleCreate(t, b, reqStorage, data)
	testRoleRead(t, b, reqStorage, defaultRoleName, expectedRole)

	// Test add appends and de-duplicates values
	toAdd := []string{"toAdd34567", "toremove@google.com", "test1@google.com"}
	expectedRole["bound_service_accounts"] = []string{
		// Initial
		"id1234",
		"test1@google.com",
		// Added values
		"toAdd34567",
		"toremove@google.com",
	}
	testRoleEditServiceAccounts(t, b, reqStorage, map[string]interface{}{
		"name": defaultRoleName,
		"add":  strings.Join(toAdd, ","),
	})
	testRoleRead(t, b, reqStorage, defaultRoleName, expectedRole)

	// Test removal of values.
	toAdd = []string{"toAdd2nd"}
	toRemove := []string{"toremove12345", "toremove@google.com"}
	expectedRole["bound_service_accounts"] = []string{
		"toAdd2nd", "id1234", "test1@google.com", "toAdd34567",
	}
	testRoleEditServiceAccounts(t, b, reqStorage, map[string]interface{}{
		"name":   defaultRoleName,
		"add":    strings.Join(toAdd, ","),
		"remove": strings.Join(toRemove, ","),
	})
	testRoleRead(t, b, reqStorage, defaultRoleName, expectedRole)
}

func TestRoleIam_MissingRequiredArgs(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	// empty type
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"project_id":             defaultProject,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyRoleType})

	// empty IAM service accounts
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       defaultRoleName,
		"type":       iamRoleType,
		"project_id": defaultProject,
	}, []string{errEmptyIamServiceAccounts})

	// empty project
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name": defaultRoleName,
		"type": iamRoleType,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyProjectId})
}

func TestRoleIam_HasGceArgs(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"type":                   iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": "aserviceaccountid",
		"bound_zone":             "us-central1-b",
		"bound_labels":           "env:test",
	}, []string{fmt.Sprintf(errTemplateInvalidRoleTypeArgs, iamRoleType, ""), "zone", "label"})

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"type":                   iamRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": "aserviceaccountid",
		"bound_region":           "us-central",
	}, []string{fmt.Sprintf(errTemplateInvalidRoleTypeArgs, iamRoleType, ""), "region"})
}

//-- GCE ROLE TESTS --
func TestRoleGce(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	serviceAccounts := []string{"aserviceaccountid"}
	defaultRoleName := "testrole"
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":       defaultRoleName,
		"type":       gceRoleType,
		"project_id": defaultProject,
	})
	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"name":                   defaultRoleName,
		"role_type":              gceRoleType,
		"project_id":             defaultProject,
		"bound_service_accounts": []string{},
	})

	serviceAccounts = []string{"aserviceaccountid", "testaccount@google.com"}
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":                   defaultRoleName,
		"policies":               "dev",
		"ttl":                    1000,
		"max_ttl":                2000,
		"period":                 30,
		"bound_zone":             "us-central-1b",
		"bound_region":           "us-central",
		"bound_instance_group":   "devGroup",
		"bound_labels":           "label1:foo,prod:true",
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"role_type":    gceRoleType,
		"project_id":   defaultProject,
		"policies":     []string{"dev"},
		"ttl":          int64(1000),
		"max_ttl":      int64(2000),
		"period":       int64(30),
		"bound_zone":   "us-central-1b",
		"bound_region": "us-central",
		"bound_labels": map[string]string{
			"label1": "foo",
			"prod":   "true",
		},
		"bound_instance_group":   "devGroup",
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleGce_EditLabels(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	labels := map[string]string{
		"label1": "toReplace",
		"foo":    "bar",
	}
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":         defaultRoleName,
		"type":         gceRoleType,
		"project_id":   defaultProject,
		"bound_labels": createGceLabelsString(labels),
	})
	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"name":         defaultRoleName,
		"role_type":    gceRoleType,
		"project_id":   defaultProject,
		"bound_labels": labels,
	})

	testRoleEditLabels(t, b, reqStorage, map[string]interface{}{
		"name": defaultRoleName,
		"add":  "label1:replace,toAdd:value",
	})
	labels["label1"] = "replace"
	labels["toAdd"] = "value"
	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"name":         defaultRoleName,
		"role_type":    gceRoleType,
		"project_id":   defaultProject,
		"bound_labels": labels,
	})

	testRoleEditLabels(t, b, reqStorage, map[string]interface{}{
		"name":   defaultRoleName,
		"add":    "add2:foo",
		"remove": "foo, toAdd",
	})
	labels["add2"] = "foo"
	delete(labels, "foo")
	delete(labels, "toAdd")
	testRoleRead(t, b, reqStorage, defaultRoleName, map[string]interface{}{
		"name":         defaultRoleName,
		"role_type":    gceRoleType,
		"project_id":   defaultProject,
		"bound_labels": labels,
	})
}

//-- BASE ROLE TESTS --
func TestRole_MissingRequiredArgs(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	// empty type
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       defaultRoleName,
		"project_id": defaultProject,
	}, []string{"role type", errEmptyRoleType})

	// empty IAM service accounts
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       defaultRoleName,
		"type":       iamRoleType,
		"project_id": defaultProject,
	}, []string{errEmptyIamServiceAccounts})

	// empty project
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name": defaultRoleName,
		"type": iamRoleType,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyProjectId})
}

func TestRole_InvalidRoleType(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	// incorrect type
	invalidRoleType := "not-a-role-type"
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       defaultRoleName,
		"type":       invalidRoleType,
		"project_id": defaultProject,
	}, []string{"role type", invalidRoleType, "is invalid"})
}

//-- Utils --
func testRoleCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleEditServiceAccounts(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s/service-accounts", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleEditLabels(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s/labels", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleCreateError(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, expected []string) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error containing: %s", strings.Join(expected, ", "))
	}

	for _, str := range expected {
		if !strings.Contains(resp.Error().Error(), str) {
			t.Fatalf("expected %s to be in error %v", str, resp.Error())
		}
	}
}

func testRoleRead(t *testing.T, b logical.Backend, s logical.Storage, roleName string, expected map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	if err := checkData(resp, expected, expectedDefaults); err != nil {
		t.Fatal(err)
	}
}

func checkData(resp *logical.Response, expected map[string]interface{}, expectedDefault map[string]interface{}) error {
	for k, actualVal := range resp.Data {
		expectedVal, ok := expected[k]
		if !ok {
			expectedVal, ok = expectedDefault[k]
			if !ok {
				return fmt.Errorf("must provide expected value for '%s' for test", k)
			}
		}

		var isEqual bool
		switch actualVal.(type) {
		case []string:
			actual := actualVal.([]string)
			expected := expectedVal.([]string)
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				strutil.EquivalentSlices(actual, expected)
		case map[string]string:
			actual := actualVal.(map[string]string)
			expected := expectedVal.(map[string]string)
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				reflect.DeepEqual(actualVal, expectedVal)
		default:
			isEqual = actualVal == expectedVal
		}

		if !isEqual {
			return fmt.Errorf("%s mismatch, expected: %v but got %v", k, actualVal, expectedVal)
		}
	}
	return nil
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
		expectedVal = []string{}
	}
	if !policyutil.EquivalentPolicies(resp.Data["policies"].([]string), expectedVal.([]string)) {
		return fmt.Errorf("policies mismatch, expected %v but got %v", expectedVal, resp.Data["policies"])
	}
	return nil
}

func createGceLabelsString(labels map[string]string) string {
	labelList := []string{}
	for k, v := range labels {
		labelList = append(labelList, fmt.Sprintf("%s:%s", k, v))
	}
	return strings.Join(labelList, ",")
}
