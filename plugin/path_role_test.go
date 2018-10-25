package gcpauth

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"reflect"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
)

// Defaults for verifying response data. If a value is not included here, it must be included in the
// 'expected' map param for a test.
var expectedDefaults map[string]interface{} = map[string]interface{}{
	"policies":               []string{"default"},
	"ttl":                    time.Duration(baseRoleFieldSchema["ttl"].Default.(int)),
	"max_ttl":                time.Duration(baseRoleFieldSchema["ttl"].Default.(int)),
	"period":                 time.Duration(baseRoleFieldSchema["ttl"].Default.(int)),
	"bound_service_accounts": []string{},
	// IAM
	"max_jwt_exp":         time.Duration(iamOnlyFieldSchema["max_jwt_exp"].Default.(int)),
	"allow_gce_inference": iamOnlyFieldSchema["allow_gce_inference"].Default.(bool),
	// GCE
	"bound_zones":           []string{},
	"bound_regions":         []string{},
	"bound_instance_groups": []string{},
	"bound_labels":          map[string]string{},
}

//-- IAM ROLE TESTS --
func TestRoleUpdateIam(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	serviceAccounts := []string{"dev1@project-123456.iam.gserviceaccounts.com", "aserviceaccountid"}

	roleName, projectId := testRoleAndProject(t)

	// Bare minimum for iam roles
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": serviceAccounts,
	})

	serviceAccounts = append(serviceAccounts, "testaccount@google.com")
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"policies":               "dev",
		"ttl":                    1000,
		"max_ttl":                2000,
		"period":                 30,
		"max_jwt_exp":            20 * 60,
		"allow_gce_inference":    false,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"type":                   iamRoleType,
		"project_id":             projectId,
		"policies":               []string{"dev"},
		"ttl":                    time.Duration(1000),
		"max_ttl":                time.Duration(2000),
		"period":                 time.Duration(30),
		"max_jwt_exp":            time.Duration(20 * 60),
		"allow_gce_inference":    false,
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleIam_Wildcard(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	serviceAccounts := []string{"*", "dev1@project-123456.iam.gserviceaccounts.com", "aserviceaccountid"}

	roleName, projectId := testRoleAndProject(t)

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	}, []string{
		fmt.Sprintf("cannot provide IAM service account wildcard '%s' (for all service accounts) with other service accounts", serviceAccountsWildcard),
	})

	serviceAccounts = []string{"*"}
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleIam_EditServiceAccounts(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	initial := []string{"id1234", "test1@google.com"}
	data := map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": strings.Join(initial, ","),
	}
	expectedRole := map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": initial,
	}

	testRoleCreate(t, b, reqStorage, data)
	testRoleRead(t, b, reqStorage, roleName, expectedRole)

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
		"name": roleName,
		"add":  strings.Join(toAdd, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, expectedRole)

	// Test removal of values.
	toAdd = []string{"toAdd2nd"}
	toRemove := []string{"toremove12345", "toremove@google.com"}
	expectedRole["bound_service_accounts"] = []string{
		"toAdd2nd", "id1234", "test1@google.com", "toAdd34567",
	}
	testRoleEditServiceAccounts(t, b, reqStorage, map[string]interface{}{
		"name":   roleName,
		"add":    strings.Join(toAdd, ","),
		"remove": strings.Join(toRemove, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, expectedRole)
}

func TestRoleIam_MissingRequiredArgs(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	// empty type
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"project_id":             projectId,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyRoleType})

	// empty IAM service accounts
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       roleName,
		"type":       iamRoleType,
		"project_id": projectId,
	}, []string{errEmptyIamServiceAccounts})

	// empty project
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyProjectId})
}

func TestRoleIam_HasGceArgs(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": "aserviceaccountid",
		"bound_zone":             "us-central1-b",
		"bound_labels":           "env:test",
	}, []string{fmt.Sprintf(errTemplateInvalidRoleTypeArgs, iamRoleType, ""), "zone", "label"})

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"project_id":             projectId,
		"bound_service_accounts": "aserviceaccountid",
		"bound_region":           "us-central",
	}, []string{fmt.Sprintf(errTemplateInvalidRoleTypeArgs, iamRoleType, ""), "region"})
}

//-- GCE ROLE TESTS --
func TestRoleGce(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":       roleName,
		"type":       gceRoleType,
		"project_id": projectId,
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"type":                   gceRoleType,
		"project_id":             projectId,
		"bound_service_accounts": []string{},
	})

	serviceAccounts := []string{"aserviceaccountid", "testaccount@google.com"}
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"policies":               "dev",
		"ttl":                    1000,
		"max_ttl":                2000,
		"period":                 30,
		"bound_zones":            "us-central-1b",
		"bound_regions":          "us-central",
		"bound_instance_groups":  "devGroup",
		"bound_labels":           "label1:foo,prod:true",
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"type":          gceRoleType,
		"project_id":    projectId,
		"policies":      []string{"dev"},
		"ttl":           time.Duration(1000),
		"max_ttl":       time.Duration(2000),
		"period":        time.Duration(30),
		"bound_zones":   []string{"us-central-1b"},
		"bound_regions": []string{"us-central"},
		"bound_labels": map[string]string{
			"label1": "foo",
			"prod":   "true",
		},
		"bound_instance_groups":  []string{"devGroup"},
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleGce_EditLabels(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	labels := map[string]string{
		"label1": "toReplace",
		"foo":    "bar",
	}
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":         roleName,
		"type":         gceRoleType,
		"project_id":   projectId,
		"bound_labels": createGceLabelsString(labels),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":         roleName,
		"type":         gceRoleType,
		"project_id":   projectId,
		"bound_labels": labels,
	})

	testRoleEditLabels(t, b, reqStorage, map[string]interface{}{
		"name": roleName,
		"add":  "label1:replace,toAdd:value",
	})
	labels["label1"] = "replace"
	labels["toAdd"] = "value"
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":         roleName,
		"type":         gceRoleType,
		"project_id":   projectId,
		"bound_labels": labels,
	})

	testRoleEditLabels(t, b, reqStorage, map[string]interface{}{
		"name":   roleName,
		"add":    "add2:foo",
		"remove": "foo, toAdd",
	})
	labels["add2"] = "foo"
	delete(labels, "foo")
	delete(labels, "toAdd")
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":         roleName,
		"type":         gceRoleType,
		"project_id":   projectId,
		"bound_labels": labels,
	})
}

func TestRoleGce_DeprecatedFields(t *testing.T) {
	t.Parallel()

	t.Run("deprecated_fields_upgraded", func(t *testing.T) {
		t.Parallel()

		b, storage := getTestBackend(t)

		roleName, projectId := testRoleAndProject(t)

		// Send the old fields
		testRoleCreate(t, b, storage, map[string]interface{}{
			"name":                 roleName,
			"type":                 gceRoleType,
			"project_id":           projectId,
			"bound_region":         "us-east1",
			"bound_zone":           "us-east1-a",
			"bound_instance_group": "my-ig",
		})

		// Ensure it's the new fields
		testRoleRead(t, b, storage, roleName, map[string]interface{}{
			"name":                  roleName,
			"type":                  gceRoleType,
			"project_id":            projectId,
			"bound_regions":         []string{"us-east1"},
			"bound_zones":           []string{"us-east1-a"},
			"bound_instance_groups": []string{"my-ig"},
		})
	})

	t.Run("existing_storage_upgraded", func(t *testing.T) {
		t.Parallel()

		b, storage := getTestBackend(t)

		roleName, projectId := testRoleAndProject(t)

		// Direct write to storage to simulate an existing installation with the
		// old data structure
		if err := storage.Put(context.Background(), &logical.StorageEntry{
			Key: "role/" + roleName,
			Value: []byte(`{
				"bound_region": "us-east1",
				"bound_zone": "us-east1-a",
				"bound_instance_group": "my-ig"
			}`),
		}); err != nil {
			t.Fatal(err)
		}

		// Read the data force an upgrade
		testRoleRead(t, b, storage, roleName, map[string]interface{}{
			"name":                  roleName,
			"type":                  gceRoleType,
			"project_id":            projectId,
			"bound_regions":         []string{"us-east1"},
			"bound_zones":           []string{"us-east1-a"},
			"bound_instance_groups": []string{"my-ig"},
		})

		// Double-check the raw storage has been updated
		entry, err := storage.Get(context.Background(), "role/"+roleName)
		if err != nil {
			t.Fatal(err)
		}

		var m map[string][]string
		if err := entry.DecodeJSON(&m); err != nil {
			t.Fatal(err)
		}

		exp := []string{"us-east1"}
		if v, ok := m["bound_regions"]; !ok || !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}

		exp = []string{"us-east1-a"}
		if v, ok := m["bound_zones"]; !ok || !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}

		exp = []string{"my-ig"}
		if v, ok := m["bound_instance_groups"]; !ok || !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})
}

//-- BASE ROLE TESTS --
func TestRole_MissingRequiredArgs(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	// empty type
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       roleName,
		"project_id": projectId,
	}, []string{"role type", errEmptyRoleType})

	// empty IAM service accounts
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       roleName,
		"type":       iamRoleType,
		"project_id": projectId,
	}, []string{errEmptyIamServiceAccounts})

	// empty project
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyProjectId})
}

func TestRole_InvalidRoleType(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	roleName, projectId := testRoleAndProject(t)

	// incorrect type
	invalidRoleType := "not-a-role-type"
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":       roleName,
		"type":       invalidRoleType,
		"project_id": projectId,
	}, []string{"role type", invalidRoleType, "is invalid"})
}

//-- Utils --
func testRoleCreate(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleUpdate(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleEditServiceAccounts(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s/service-accounts", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleEditLabels(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s/labels", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleCreateError(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}, expected []string) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		tb.Fatalf("expected error containing: %s", strings.Join(expected, ", "))
	}

	for _, str := range expected {
		if !strings.Contains(resp.Error().Error(), str) {
			tb.Fatalf("expected %s to be in error %v", str, resp.Error())
		}
	}
}

func testRoleRead(tb testing.TB, b logical.Backend, s logical.Storage, roleName string, expected map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}

	if err := checkData(resp, expected, expectedDefaults); err != nil {
		tb.Fatal(err)
	}
}

func checkData(resp *logical.Response, expected map[string]interface{}, expectedDefault map[string]interface{}) error {
	for k, actualVal := range resp.Data {
		expectedVal, ok := expected[k]
		if !ok {
			expectedVal, ok = expectedDefault[k]
			if !ok {
				return fmt.Errorf("must provide expected value for %q for test", k)
			}
		}

		var isEqual bool
		switch actualVal.(type) {
		case []string:
			actual := actualVal.([]string)
			expected, ok := expectedVal.([]string)
			if !ok {
				return fmt.Errorf("%s type mismatch: expected type %T, actual type %T", k, expectedVal, actualVal)
			}
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				strutil.EquivalentSlices(actual, expected)
		case map[string]string:
			actual := actualVal.(map[string]string)
			expected, ok := expectedVal.(map[string]string)
			if !ok {
				return fmt.Errorf("%s type mismatch: expected type %T, actual type %T", k, expectedVal, actualVal)
			}
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				reflect.DeepEqual(actualVal, expectedVal)
		default:
			isEqual = actualVal == expectedVal
		}

		if !isEqual {
			return fmt.Errorf("%s mismatch, expected: %v but got %v", k, expectedVal, actualVal)
		}
	}
	return nil
}

func testBaseRoleRead(resp *logical.Response, expected map[string]interface{}) error {
	expectedVal, ok := expected["type"]
	if ok && resp.Data["type"].(string) != expectedVal.(string) {
		return fmt.Errorf("role type mismatch, expected %s but got %s", expectedVal, resp.Data["type"])
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

// testRoleAndProject generates a unique name for a role and project.
func testRoleAndProject(tb testing.TB) (string, string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	suffix := fmt.Sprintf("%d", r.Intn(1000000))

	roleName := "v-auth-" + suffix
	projectId := "v-project-" + suffix

	return roleName, projectId
}
