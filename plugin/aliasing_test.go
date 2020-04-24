package gcpauth

import (
	"testing"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
)

func TestGetIAMAlias(t *testing.T) {
	type testCase struct {
		role          *gcpRole
		svcAccount    *iam.ServiceAccount
		expectedAlias string
		expectErr     bool
	}

	tests := map[string]testCase{
		"invalid type": {
			role: &gcpRole{
				IAMAliasType: "bogus",
				RoleID:       "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "",
			expectErr:     true,
		},
		"empty type goes to default": {
			role: &gcpRole{
				IAMAliasType: "",
				RoleID:       "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "iamUniqueID",
			expectErr:     false,
		},
		"default type": {
			role: &gcpRole{
				IAMAliasType: defaultIAMAlias,
				RoleID:       "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "iamUniqueID",
			expectErr:     false,
		},
		"role_id": {
			role: &gcpRole{
				IAMAliasType: "role_id",
				RoleID:       "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "testRoleID",
			expectErr:     false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualAlias, err := getIAMAlias(test.role, test.svcAccount)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if actualAlias != test.expectedAlias {
				t.Fatalf("Actual alias: %s Expected Alias: %s", actualAlias, test.expectedAlias)
			}
		})
	}
}

func TestGetGCEAlias(t *testing.T) {
	type testCase struct {
		role          *gcpRole
		instance      *compute.Instance
		expectedAlias string
		expectErr     bool
	}

	tests := map[string]testCase{
		"invalid type": {
			role: &gcpRole{
				GCEAliasType: "bogus",
				RoleID:       "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "",
			expectErr:     true,
		},
		"empty type goes to default": {
			role: &gcpRole{
				GCEAliasType: "",
				RoleID:       "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "gce-123",
			expectErr:     false,
		},
		"default type": {
			role: &gcpRole{
				GCEAliasType: defaultGCEAlias,
				RoleID:       "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "gce-123",
			expectErr:     false,
		},
		"role_id": {
			role: &gcpRole{
				GCEAliasType: "role_id",
				RoleID:       "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "testRoleID",
			expectErr:     false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualAlias, err := getGCEAlias(test.role, test.instance)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if actualAlias != test.expectedAlias {
				t.Fatalf("Actual alias: %s Expected Alias: %s", actualAlias, test.expectedAlias)
			}
		})
	}
}
