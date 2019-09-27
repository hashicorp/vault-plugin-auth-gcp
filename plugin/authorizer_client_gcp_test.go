package gcpauth

import (
	"testing"
	"google.golang.org/api/compute/v1"
)

func TestInstanceGroups(t *testing.T) {

	igz := make(map[string][]string)
	boundInstanceGroups := []string{"foo-us1-baz-group"}

	extractZonesFn := genExtractZonesFn(igz, boundInstanceGroups)


	InstanceGroupAggregatedList := compute.InstanceGroupAggregatedList{
		Items: map[string]compute.InstanceGroupsScopedList{
			"zones/us-central1-c": compute.InstanceGroupsScopedList{
				InstanceGroups: []*compute.InstanceGroup{&compute.InstanceGroup{Name: "foo-us1-bar-group"}, &compute.InstanceGroup{Name: "foo-us1-baz-group"}},
			},
			"regions/us-central1": compute.InstanceGroupsScopedList{},
		},
	}

	err := extractZonesFn(&InstanceGroupAggregatedList)

	if err != nil {
		t.Fatal("error not expected")
	}

	if igz["us-central1-c"][0] != "foo-us1-baz-group" {
		t.Fatal("expected value not found")
	}
}