package gcpauth

import (
	"testing"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
)

func TestGetIAMAlias(t *testing.T) {
	type testCase struct {
		config        *gcpConfig
		role          *gcpRole
		svcAccount    *iam.ServiceAccount
		expectedAlias string
		expectErr     bool
	}

	tests := map[string]testCase{
		"invalid type": {
			config: &gcpConfig{
				IAMAliasType: "bogus",
			},
			role: &gcpRole{
				RoleID: "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "",
			expectErr:     true,
		},
		"empty type goes to default": {
			config: &gcpConfig{
				IAMAliasType: "",
			},
			role: &gcpRole{
				RoleID: "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "iamUniqueID",
			expectErr:     false,
		},
		"default type": {
			config: &gcpConfig{
				IAMAliasType: defaultIAMAlias,
			},
			role: &gcpRole{
				RoleID: "testRoleID",
			},
			svcAccount: &iam.ServiceAccount{
				UniqueId: "iamUniqueID",
			},
			expectedAlias: "iamUniqueID",
			expectErr:     false,
		},
		"role_id": {
			config: &gcpConfig{
				IAMAliasType: "role_id",
			},
			role: &gcpRole{
				RoleID: "testRoleID",
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
			actualAlias, err := test.config.getIAMAlias(test.role, test.svcAccount)
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
		config        *gcpConfig
		role          *gcpRole
		instance      *compute.Instance
		expectedAlias string
		expectErr     bool
	}

	tests := map[string]testCase{
		"invalid type": {
			config: &gcpConfig{
				GCEAliasType: "bogus",
			},
			role: &gcpRole{
				RoleID: "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "",
			expectErr:     true,
		},
		"empty type goes to default": {
			config: &gcpConfig{
				GCEAliasType: "",
			},
			role: &gcpRole{
				RoleID: "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "gce-123",
			expectErr:     false,
		},
		"default type": {
			config: &gcpConfig{
				GCEAliasType: defaultGCEAlias,
			},
			role: &gcpRole{
				RoleID: "testRoleID",
			},
			instance: &compute.Instance{
				Id: 123,
			},
			expectedAlias: "gce-123",
			expectErr:     false,
		},
		"role_id": {
			config: &gcpConfig{
				GCEAliasType: "role_id",
			},
			role: &gcpRole{
				RoleID: "testRoleID",
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
			actualAlias, err := test.config.getGCEAlias(test.role, test.instance)
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
