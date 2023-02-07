// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpauth

import (
	"context"
	"strings"
	"testing"
)

func TestAuthorizeGCE(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		i       *AuthorizeGCEInput
		err     bool
		errText string
	}{
		// instance labels
		{
			"labels_no_match_key",
			&AuthorizeGCEInput{
				client: &stubbedClient{},
				instanceLabels: map[string]string{
					"foo": "bar",
				},
				boundLabels: map[string]string{
					"foo": "bar",
					"zip": "zap",
				},
			},
			true,
			`instance missing bound label "zip:zap"`,
		},
		{
			"labels_no_match_value",
			&AuthorizeGCEInput{
				client: &stubbedClient{},
				instanceLabels: map[string]string{
					"foo": "bar",
				},
				boundLabels: map[string]string{
					"foo": "zip",
				},
			},
			true,
			`instance missing bound label "foo:zip"`,
		},

		// instance zone
		{
			"zone_as_self_link_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-east1-a",
				boundZones:   []string{"us-east1-a", "us-west1-b"},
			},
			false,
			"",
		},
		{
			"zone_as_name_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "us-east1-a",
				boundZones:   []string{"us-east1-a", "us-west1-b"},
			},
			false,
			"",
		},
		{
			"zone_as_self_link_no_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "https://www.googleapis.com/compute/v1/projects/my-project/zones/eu-west1-a",
				boundZones:   []string{"us-east1-a", "us-west1-b"},
			},
			true,
			`instance not in bound zones ["us-east1-a" "us-west1-b"]`,
		},
		{
			"zone_as_name_no_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "eu-west1-a",
				boundZones:   []string{"us-east1-a", "us-west1-b"},
			},
			true,
			`instance not in bound zones ["us-east1-a" "us-west1-b"]`,
		},
		{
			"zone_as_invalid",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "http://google.com/foo/bar",
				boundZones:   []string{"us-east1-a", "us-west1-b"},
			},
			true,
			`failed to extract zone`,
		},

		// instance region
		{
			"region_as_self_link_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-east1-a",
				boundRegions: []string{"us-east1", "us-west1"},
			},
			false,
			"",
		},
		{
			"region_as_name_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "us-east1-a",
				boundRegions: []string{"us-east1", "us-west1"},
			},
			false,
			"",
		},
		{
			"region_as_self_link_no_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "https://www.googleapis.com/compute/v1/projects/my-project/zones/eu-west1-a",
				boundRegions: []string{"us-east1", "us-west1"},
			},
			true,
			`instance not in bound regions ["us-east1" "us-west1"]`,
		},
		{
			"region_as_name_no_exists",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "eu-west1-a",
				boundRegions: []string{"us-east1", "us-west1"},
			},
			true,
			`instance not in bound regions ["us-east1" "us-west1"]`,
		},
		{
			"region_as_invalid",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "http://google.com/foo/bar",
				boundRegions: []string{"us-east1", "us-west1"},
			},
			true,
			`failed to extract zone`,
		},

		// bound instance groups
		{
			"bound_instance_groups_unbound",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone:          map[string][]string{},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
			},
			true,
			`instance group "my-instance-group" is not bound to any zones or regions`,
		},
		{
			"bound_instance_groups_empty_bound_zones",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone:          map[string][]string{},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundZones:          []string{"us-east1-a"},
			},
			true,
			`instance group "my-instance-group" does not exist in zones ["us-east1-a"]`,
		},
		{
			"bound_instance_groups_no_exist_bound_zones",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone: map[string][]string{
						"us-east1-a": []string{"other-instance-group"},
					},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundZones:          []string{"us-east1-a"},
			},
			true,
			`instance group "my-instance-group" does not exist in zones ["us-east1-a"]`,
		},
		{
			"bound_instance_groups_empty_bound_regions",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone:          map[string][]string{},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundRegions:        []string{"us-east1"},
			},
			true,
			`instance group "my-instance-group" does not exist in regions ["us-east1"]`,
		},
		{
			"bound_instance_groups_no_exist_bound_regions",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone: map[string][]string{
						"us-east1-a": []string{"other-instance-group"},
					},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundRegions:        []string{"us-east1"},
			},
			true,
			`instance group "my-instance-group" does not exist in regions ["us-east1"]`,
		},
		{
			"bound_instance_groups_no_contains_instance",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone: map[string][]string{
						"us-east1-a": []string{"my-instance-group"},
					},
					instanceGroupContainsInstance: false,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundZones:          []string{"us-east1-a"},
			},
			true,
			`instance is not part of instance groups ["my-instance-group"]`,
		},
		{
			"bound_regional_instance_groups_no_exist_bound_regions",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByRegion: map[string][]string{
						"us-east1": []string{"other-instance-group"},
					},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundRegions:        []string{"us-east1"},
			},
			true,
			`instance group "my-instance-group" does not exist in regions ["us-east1"]`,
		},
		{
			"bound_regional_instance_groups_no_contains_instance",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByRegion: map[string][]string{
						"us-east1": []string{"my-instance-group"},
					},
					instanceGroupContainsInstance: false,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundRegions:        []string{"us-east1"},
			},
			true,
			`instance is not part of instance groups ["my-instance-group"]`,
		},

		// service account
		{
			"bound_service_account_no_exist",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					saId:    "foo",
					saEmail: "foo@bar.com",
				},
				serviceAccount:       "foo",
				instanceZone:         "us-east1-a",
				boundServiceAccounts: []string{"bar"},
			},
			true,
			`is not in bound service accounts`,
		},
		{
			"bound_service_account_id",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					saId:    "foo",
					saEmail: "foo@bar.com",
				},
				instanceZone:         "us-east1-a",
				boundServiceAccounts: []string{"foo"},
			},
			false,
			"",
		},
		{
			"bound_service_account_email",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					saId:    "foo",
					saEmail: "foo@bar.com",
				},
				instanceZone:         "us-east1-a",
				boundServiceAccounts: []string{"foo@bar.com"},
			},
			false,
			"",
		},

		// full success examples
		{
			"success_zone_binding",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "us-east1-a",
				boundZones:   []string{"us-east1-a"},
			},
			false,
			"",
		},
		{
			"success_region_binding",
			&AuthorizeGCEInput{
				client:       &stubbedClient{},
				instanceZone: "us-east1-a",
				boundRegions: []string{"us-east1"},
			},
			false,
			"",
		},
		{
			"success_instance_group_zone_binding",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone: map[string][]string{
						"us-east1-a": []string{"my-instance-group"},
						"us-east1-b": []string{"my-instance-group", "my-other-group"},
					},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundZones:          []string{"us-east1-a"},
			},
			false,
			"",
		},
		{
			"success_instance_group_region_binding",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByZone: map[string][]string{
						"us-east1-a": []string{"my-instance-group"},
						"us-east1-b": []string{"my-instance-group", "my-other-group"},
					},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundRegions:        []string{"us-east1"},
			},
			false,
			"",
		},
		{
			"success_regional_instance_group_region_binding",
			&AuthorizeGCEInput{
				client: &stubbedClient{
					instanceGroupsByRegion: map[string][]string{
						"us-east1": []string{"my-instance-group"},
					},
					instanceGroupContainsInstance: true,
				},
				instanceZone:        "us-east1-a",
				boundInstanceGroups: []string{"my-instance-group"},
				boundRegions:        []string{"us-east1"},
			},
			false,
			"",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			err := AuthorizeGCE(ctx, tc.i)
			if tc.err {
				if err == nil {
					t.Fatal("expected error")
				}

				if !strings.Contains(err.Error(), tc.errText) {
					t.Errorf("expected %q to contain %q", err.Error(), tc.errText)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
