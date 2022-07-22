package gcpauth

import (
	"fmt"
	"testing"
)

func TestZoneToRegion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		zone   string
		region string
		err    bool
	}{
		{
			"us-central1-a",
			"us-central1",
			false,
		},
		{
			"northamerica-northeast1-c",
			"northamerica-northeast1",
			false,
		},
		{
			"europe-west3-c",
			"europe-west3",
			false,
		},
		{
			"us",
			"",
			true,
		},
		{
			"",
			"",
			true,
		},
	}

	for i, tc := range cases {
		tc := tc

		name := fmt.Sprintf("%d_%s_to_%s", i, tc.zone, tc.region)
		if tc.err {
			name = fmt.Sprintf("%d_%s_err", i, tc.zone)
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			res, err := zoneToRegion(tc.zone)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if res != tc.region {
				t.Errorf("expected %q to convert to %q", tc.zone, tc.region)
			}
		})
	}
}

func TestZoneOrRegionFromSelfLink(t *testing.T) {
	t.Parallel()

	cases := []struct {
		link   string
		zone   string
		region string
		err    bool
	}{
		{
			"https://www.googleapis.com/compute/v1/projects/my-project/zones/us-east1-d",
			"us-east1-d",
			"",
			false,
		},
		{
			"https://www.googleapis.com/compute/v1/projects/my-project/regions/us-east1",
			"",
			"us-east1",
			false,
		},
		{
			"https://www.googleapis.com/compute/v1/projects/my-project/badbadbad/us-east1",
			"",
			"",
			true,
		},
		{
			"",
			"",
			"",
			true,
		},
	}

	for i, tc := range cases {
		tc := tc
		name := fmt.Sprintf("%d", i)

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			z, r, err := zoneOrRegionFromSelfLink(tc.link)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if z != tc.zone {
				t.Errorf("expected %q to convert to %q", tc.link, tc.zone)
			}
			if r != tc.region {
				t.Errorf("expected %q to convert to %q", tc.link, tc.region)
			}
		})
	}
}
