// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Defaults for verifying response data. If a value is not included here, it must be included in the
// 'expected' map param for a test.
var expectedDefaults = map[string]interface{}{
	"token_policies":          []string{},
	"policies":                []string{},
	"token_ttl":               int64(0),
	"ttl":                     int64(0),
	"token_max_ttl":           int64(0),
	"max_ttl":                 int64(0),
	"token_period":            int64(0),
	"period":                  int64(0),
	"token_explicit_max_ttl":  int64(0),
	"token_no_default_policy": false,
	"token_bound_cidrs":       []string{},
	"token_num_uses":          int(0),
	"token_type":              logical.TokenTypeDefault.String(),
	"bound_projects":          []string{},
	"bound_service_accounts":  []string{},
	"add_group_aliases":       false,
	// IAM
	"max_jwt_exp":         int64(iamOnlyFieldSchema["max_jwt_exp"].Default.(int)),
	"allow_gce_inference": iamOnlyFieldSchema["allow_gce_inference"].Default.(bool),
	// GCE
	"bound_zones":           []string{},
	"bound_regions":         []string{},
	"bound_instance_groups": []string{},
	"bound_labels":          map[string]string{},
}

// -- IAM ROLE TESTS --
func TestRoleUpdateIam(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	serviceAccounts := []string{"dev1@project-123456.iam.gserviceaccounts.com", "aserviceaccountid"}

	roleName, _ := testRoleAndProject(t)

	// Bare minimum for iam roles
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
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
		"add_group_aliases":      true,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"type":                   iamRoleType,
		"token_policies":         []string{"dev"},
		"policies":               []string{"dev"},
		"token_ttl":              int64(1000),
		"ttl":                    int64(1000),
		"token_max_ttl":          int64(2000),
		"max_ttl":                int64(2000),
		"token_period":           int64(30),
		"period":                 int64(30),
		"max_jwt_exp":            int64(20 * 60),
		"allow_gce_inference":    false,
		"add_group_aliases":      true,
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleIam_Wildcard(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	serviceAccounts := []string{"*", "dev1@project-123456.iam.gserviceaccounts.com", "aserviceaccountid"}

	roleName, _ := testRoleAndProject(t)

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	}, []string{
		fmt.Sprintf("cannot provide IAM service account wildcard '%s' (for all service accounts) with other service accounts", serviceAccountsWildcard),
	})

	serviceAccounts = []string{"*"}
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_service_accounts": strings.Join(serviceAccounts, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"type":                   iamRoleType,
		"bound_service_accounts": serviceAccounts,
	})
}

func TestRoleIam_EditServiceAccounts(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	roleName, projectId := testRoleAndProject(t)
	projects := []string{projectId, "another-project"}
	initial := []string{"id1234", "test1@google.com"}
	data := map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_projects":         strings.Join(projects, ","),
		"bound_service_accounts": strings.Join(initial, ","),
	}
	expectedRole := map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_projects":         projects,
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

	b, reqStorage := testBackend(t)

	roleName, _ := testRoleAndProject(t)

	// empty type
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"bound_service_accounts": "aserviceaccountid",
	}, []string{errEmptyRoleType})

	// empty IAM service accounts
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name": roleName,
		"type": iamRoleType,
	}, []string{errEmptyIamServiceAccounts})
}

func TestRoleIam_HasGceArgs(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	roleName, projectId := testRoleAndProject(t)

	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"type":                   iamRoleType,
		"bound_projects":         projectId,
		"bound_service_accounts": "aserviceaccountid",
		"bound_zones":            "us-central1-b",
	}, []string{fmt.Sprintf(errTemplateInvalidRoleTypeArgs, iamRoleType, ""), "bound_zones"})
}

// -- GCE ROLE TESTS --
func TestRoleGce(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	roleName, projectId := testRoleAndProject(t)

	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name": roleName,
		"type": gceRoleType,
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"type":                   gceRoleType,
		"bound_projects":         []string{},
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
		"add_group_aliases":      true,
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"type":           gceRoleType,
		"bound_projects": projectId,
		"token_policies": []string{"dev"},
		"policies":       []string{"dev"},
		"token_ttl":      int64(1000),
		"ttl":            int64(1000),
		"token_max_ttl":  int64(2000),
		"max_ttl":        int64(2000),
		"token_period":   int64(30),
		"period":         int64(30),
		"bound_zones":    []string{"us-central-1b"},
		"bound_regions":  []string{"us-central"},
		"bound_labels": map[string]string{
			"label1": "foo",
			"prod":   "true",
		},
		"bound_instance_groups":  []string{"devGroup"},
		"bound_service_accounts": serviceAccounts,
		"add_group_aliases":      true,
	})
}

func TestRoleGce_EditLabels(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	roleName, projectId := testRoleAndProject(t)

	labels := map[string]string{
		"label1": "toReplace",
		"foo":    "bar",
	}
	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":           roleName,
		"type":           gceRoleType,
		"bound_projects": projectId,
		"bound_labels":   createGceLabelsString(labels),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":           roleName,
		"type":           gceRoleType,
		"bound_projects": []string{projectId},
		"bound_labels":   labels,
	})

	testRoleEditLabels(t, b, reqStorage, map[string]interface{}{
		"name": roleName,
		"add":  "label1:replace,toAdd:value",
	})
	labels["label1"] = "replace"
	labels["toAdd"] = "value"
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":           roleName,
		"type":           gceRoleType,
		"bound_projects": []string{projectId},
		"bound_labels":   labels,
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
		"name":           roleName,
		"type":           gceRoleType,
		"bound_projects": []string{projectId},
		"bound_labels":   labels,
	})
}

func TestRoleGce_DeprecatedFields(t *testing.T) {
	t.Parallel()

	t.Run("deprecated_fields_upgraded", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

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
			"bound_projects":        []string{projectId},
			"bound_regions":         []string{"us-east1"},
			"bound_zones":           []string{"us-east1-a"},
			"bound_instance_groups": []string{"my-ig"},
		})
	})

	t.Run("existing_storage_upgraded", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

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
			"bound_projects":        projectId,
			"bound_regions":         []string{"us-east1"},
			"bound_zones":           []string{"us-east1-a"},
			"bound_instance_groups": []string{"my-ig"},
		})

		// Double-check the raw storage has been updated
		entry, err := storage.Get(context.Background(), "role/"+roleName)
		if err != nil {
			t.Fatal(err)
		}

		var m map[string]interface{}
		if err := entry.DecodeJSON(&m); err != nil {
			t.Fatal(err)
		}

		exp := []interface{}{"us-east1"}
		if v, ok := m["bound_regions"]; !ok || !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}

		exp = []interface{}{"us-east1-a"}
		if v, ok := m["bound_zones"]; !ok || !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}

		exp = []interface{}{"my-ig"}
		if v, ok := m["bound_instance_groups"]; !ok || !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})
}

// -- BASE ROLE TESTS --
func TestRole_MissingRequiredArgs(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)

	roleName, projectId := testRoleAndProject(t)

	// empty type
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":           roleName,
		"bound_projects": projectId,
	}, []string{"role type", errEmptyRoleType})

	// empty IAM service accounts
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":           roleName,
		"type":           iamRoleType,
		"bound_projects": projectId,
	}, []string{errEmptyIamServiceAccounts})
}

func TestRole_InvalidRoleType(t *testing.T) {
	b, reqStorage := testBackend(t)

	roleName, projectId := testRoleAndProject(t)

	// incorrect type
	invalidRoleType := "not-a-role-type"
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name":           roleName,
		"type":           invalidRoleType,
		"bound_projects": projectId,
	}, []string{"role type", invalidRoleType, "is invalid"})
}

func TestRetrieveRole(t *testing.T) {
	type testCase struct {
		name string

		getName  string
		getResp  *logical.StorageEntry
		getErr   error
		getTimes int

		localMount            bool
		localMountTimes       int
		replicationState      consts.ReplicationState
		replicationStateTimes int

		putTimes int

		expectedRole *gcpRole
		expectErr    bool
	}

	tests := map[string]testCase{
		"not found": {
			name: "testrole",

			getName:  "role/testrole",
			getResp:  nil,
			getErr:   nil,
			getTimes: 1,

			localMountTimes:       0,
			replicationStateTimes: 0,

			expectedRole: nil,
			expectErr:    false,
		},
		"storage error": {
			name: "testrole",

			getName:  "role/testrole",
			getResp:  nil,
			getErr:   fmt.Errorf("test error"),
			getTimes: 1,

			localMountTimes:       0,
			replicationStateTimes: 0,

			expectedRole: nil,
			expectErr:    true,
		},
		"bad data": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key:   "role/testrole",
				Value: []byte("asdfhoiasndf"),
			},
			getErr:   nil,
			getTimes: 1,

			localMountTimes:       0,
			replicationStateTimes: 0,

			expectedRole: nil,
			expectErr:    true,
		},
		"projectID upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:        "testroleid",
						ProjectId:     "projectID",
						BoundProjects: []string{},
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID:        "testroleid",
				BoundProjects: []string{"projectID"},
			},
			expectErr: false,
		},
		"boundRegion upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:       "testroleid",
						BoundRegion:  "boundRegion",
						BoundRegions: []string{},
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID:       "testroleid",
				BoundRegions: []string{"boundRegion"},
			},
			expectErr: false,
		},
		"boundZone upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:     "testroleid",
						BoundZone:  "boundZone",
						BoundZones: []string{},
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID:     "testroleid",
				BoundZones: []string{"boundZone"},
			},
			expectErr: false,
		},
		"boundInstanceGroup upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:              "testroleid",
						BoundInstanceGroup:  "boundInstanceGroup",
						BoundInstanceGroups: []string{},
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID:              "testroleid",
				BoundInstanceGroups: []string{"boundInstanceGroup"},
			},
			expectErr: false,
		},
		"TTL upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:      "testroleid",
						TokenParams: tokenutil.TokenParams{},
						TTL:         1 * time.Second,
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID: "testroleid",
				TokenParams: tokenutil.TokenParams{
					TokenTTL: 1 * time.Second,
				},
				TTL: 1 * time.Second,
			},
			expectErr: false,
		},
		"MaxTTL upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:      "testroleid",
						TokenParams: tokenutil.TokenParams{},
						MaxTTL:      1 * time.Second,
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID: "testroleid",
				TokenParams: tokenutil.TokenParams{
					TokenMaxTTL: 1 * time.Second,
				},
				MaxTTL: 1 * time.Second,
			},
			expectErr: false,
		},
		"TokenPeriod upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:      "testroleid",
						TokenParams: tokenutil.TokenParams{},
						Period:      1 * time.Second,
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID: "testroleid",
				TokenParams: tokenutil.TokenParams{
					TokenPeriod: 1 * time.Second,
				},
				Period: 1 * time.Second,
			},
			expectErr: false,
		},
		"TokenPolicies upgrade": {
			name: "testrole",

			getName: "role/testrole",
			getResp: &logical.StorageEntry{
				Key: "testrole",
				Value: toJSON(t,
					gcpRole{
						RoleID:      "testroleid",
						TokenParams: tokenutil.TokenParams{},
						Policies:    []string{"policy1", "policy2"},
					}),
			},
			getErr:   nil,
			getTimes: 1,

			localMount:            true,
			localMountTimes:       1,
			replicationStateTimes: 0,

			putTimes: 1,

			expectedRole: &gcpRole{
				RoleID: "testroleid",
				TokenParams: tokenutil.TokenParams{
					TokenPolicies: []string{"policy1", "policy2"},
				},
				Policies: []string{"policy1", "policy2"},
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()

			storage := NewMockStorage(ctrl)
			storage.EXPECT().Get(ctx, test.getName).Return(test.getResp, test.getErr).Times(test.getTimes)

			putReq := &logical.StorageEntry{
				Key:   fmt.Sprintf("role/%s", test.name),
				Value: append(toJSON(t, test.expectedRole), '\n'), // Add a newline because StorageEntryJSON somehow adds it
			}
			storage.EXPECT().Put(ctx, putReq).Return(nil).Times(test.putTimes)

			systemView := NewMockSystemView(ctrl)
			systemView.EXPECT().LocalMount().Return(test.localMount).Times(test.localMountTimes)
			systemView.EXPECT().ReplicationState().Return(test.replicationState).Times(test.replicationStateTimes)

			be, err := Factory(ctx, &logical.BackendConfig{System: systemView})
			if err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			b := be.(*GcpAuthBackend)

			actualResp, err := b.role(ctx, storage, test.name)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if !reflect.DeepEqual(actualResp, test.expectedRole) {
				t.Fatalf("Actual role: %#v\nExpected role: %#v", actualResp, test.expectedRole)
			}
		})
	}

	t.Run("storage put error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		name := "testrole"

		getResp := &logical.StorageEntry{
			Key: "testrole",
			Value: toJSON(t,
				gcpRole{
					RoleID:    "testroleid",
					ProjectId: "projectID",
				}),
		}

		putReq := &logical.StorageEntry{
			Key: fmt.Sprintf("role/%s", name),
			Value: append(toJSON(t,
				gcpRole{
					RoleID:        "testroleid",
					BoundProjects: []string{"projectID"},
				},
			), '\n'), // Add a newline because StorageEntryJSON somehow adds it
		}

		storage := NewMockStorage(ctrl)
		storage.EXPECT().Get(ctx, fmt.Sprintf("role/%s", name)).Return(getResp, nil)
		storage.EXPECT().Put(ctx, putReq).Return(fmt.Errorf("test error"))

		systemView := NewMockSystemView(ctrl)
		systemView.EXPECT().LocalMount().Return(true)

		be, err := Factory(ctx, &logical.BackendConfig{System: systemView})
		if err != nil {
			t.Fatalf("no error expected, got: %s", err)
		}
		b := be.(*GcpAuthBackend)

		actualResp, err := b.role(ctx, storage, name)
		if err == nil {
			t.Fatalf("err expected, got nil")
		}
		if actualResp != nil {
			t.Fatalf("no role expected, but got: %#v", actualResp)
		}
	})

	t.Run("roleID is generated when one does not exist", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		name := "testrole"

		getResp := &logical.StorageEntry{
			Key: "testrole",
			Value: toJSON(t,
				gcpRole{}),
		}

		storage := NewMockStorage(ctrl)
		storage.EXPECT().Get(ctx, fmt.Sprintf("role/%s", name)).Return(getResp, nil)

		var actualRawPut *logical.StorageEntry
		storage.EXPECT().Put(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, put *logical.StorageEntry) error {
			actualRawPut = put
			return nil
		})

		systemView := NewMockSystemView(ctrl)
		systemView.EXPECT().LocalMount().Return(true)

		be, err := Factory(ctx, &logical.BackendConfig{System: systemView})
		if err != nil {
			t.Fatalf("no error expected, got: %s", err)
		}
		b := be.(*GcpAuthBackend)

		actualRole, err := b.role(ctx, storage, name)
		if err != nil {
			t.Fatalf("no err expected, got: %s", err)
		}

		if actualRole.RoleID == "" {
			t.Fatalf("RoleID not set on returned role")
		}

		expectedPutKey := fmt.Sprintf("role/%s", name)
		if actualRawPut.Key != expectedPutKey {
			t.Fatalf("Actual put key: %s Expected put key: %s", actualRawPut.Key, expectedPutKey)
		}

		putRole := gcpRole{}
		err = json.Unmarshal(actualRawPut.Value, &putRole)
		if err != nil {
			t.Fatalf("no err expected, got: %s", err)
		}

		if putRole.RoleID != actualRole.RoleID {
			t.Fatalf("Saved RoleID [%s] does not match returned RoleID [%s]", putRole.RoleID, actualRole.RoleID)
		}
	})
}

// -- Utils --
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

	// Because role_id is generated, ensure that it exists but don't worry about the specific value
	roleID, exists := resp.Data["role_id"]
	if !exists || roleID == "" {
		tb.Fatal("missing or empty role_id")
	}
	delete(resp.Data, "role_id")

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

func toJSON(t testing.TB, val interface{}) []byte {
	t.Helper()

	b, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %s", err)
	}
	return b
}
