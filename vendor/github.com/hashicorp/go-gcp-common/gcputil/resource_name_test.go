package gcputil

import (
	"testing"
)

func TestParseSelfLink(t *testing.T) {
	testCases := map[string]struct {
		Expected    *SelfLink
		ShouldError bool
	}{
		"":                                            {ShouldError: true},
		"not/a/real/link":                             {ShouldError: true},
		"//fullresourcename.google.com/foo/A":         {ShouldError: true},
		"https://aprojectlesslink.com/v1/foo/A/bar/B": {ShouldError: true},
		"https://validlink.com/v1/projects/A/foos/B": {
			ShouldError: false,
			Expected: &SelfLink{
				Prefix: "https://validlink.com/v1/",
				RelativeResourceName: &RelativeResourceName{
					Name:    "foos",
					TypeKey: "projects/foos",
					IdTuples: map[string]string{
						"projects": "A",
						"foos":     "B",
					},
					OrderedCollectionIds: []string{"projects", "foos"},
				},
			},
		},
	}

	for k, testCase := range testCases {
		actual, err := ParseProjectResourceSelfLink(k)

		if testCase.ShouldError && err == nil {
			t.Errorf("input '%s' should have returned error, instead got: %v", k, actual)
		} else if !testCase.ShouldError {
			if err != nil {
				t.Errorf("input '%s' returned error: %s", k, err)
			} else {
				if testCase.Expected.Prefix != actual.Prefix {
					t.Errorf("input '%s' prefix, expected %s, got %s", k, testCase.Expected.Prefix, actual.Prefix)
					continue
				}
				checkRelativeName(t, k, testCase.Expected.RelativeResourceName, actual.RelativeResourceName)
			}
		}
	}
}

func TestParseFullResourceName(t *testing.T) {
	testCases := map[string]struct {
		Expected    *FullResourceName
		ShouldError bool
	}{
		"":                                          {ShouldError: true},
		"not/a/real/link":                           {ShouldError: true},
		"https://aselflink.com/v1/foo/A/bar/B":      {ShouldError: true},
		"https://a.fake.service.com/v1/foo/A/bar/B": {ShouldError: true},
		"//aservice.googleapis.com/foos/A/bars/B": {
			ShouldError: false,
			Expected: &FullResourceName{
				Service: "aservice",
				RelativeResourceName: &RelativeResourceName{
					Name:    "bars",
					TypeKey: "foos/bars",
					IdTuples: map[string]string{
						"foos": "A",
						"bars": "B",
					},
					OrderedCollectionIds: []string{"foos", "bars"},
				},
			},
		},
	}

	for k, testCase := range testCases {
		actual, err := ParseFullResourceName(k)

		if testCase.ShouldError && err == nil {
			t.Errorf("input '%s' should have returned error, instead got: %v", k, actual)
		} else if !testCase.ShouldError {
			if err != nil {
				t.Errorf("input '%s' returned error: %s", k, err)
			} else {
				if testCase.Expected.Service != actual.Service {
					t.Errorf("input '%s' service, expected %s, got %s", k, testCase.Expected.Service, actual.Service)
					continue
				}
				checkRelativeName(t, k, testCase.Expected.RelativeResourceName, actual.RelativeResourceName)
			}
		}
	}
}

func TestParseRelativeName_noErrors(t *testing.T) {
	testCases := map[string]*RelativeResourceName{
		"projects/my-project": {
			Name:    "projects",
			TypeKey: "projects",
			IdTuples: map[string]string{
				"projects": "my-project",
			},
			OrderedCollectionIds: []string{"projects"},
		},
		"foos/bar@": {
			Name:    "foos",
			TypeKey: "foos",
			IdTuples: map[string]string{
				"foos": "bar@",
			},
			OrderedCollectionIds: []string{"foos"},
		},
		"foos/1/bars/2": {
			Name:    "bars",
			TypeKey: "foos/bars",
			IdTuples: map[string]string{
				"foos": "1",
				"bars": "2",
			},
			OrderedCollectionIds: []string{"foos", "bars"},
		},
		"foo/1/global/bar/2": {
			Name:    "bar",
			TypeKey: "foo/bar",
			IdTuples: map[string]string{
				"foo": "1",
				"bar": "2",
			},
			OrderedCollectionIds: []string{"foo", "bar"},
		},
		"foos/{foosId}/global/bars/{barsId}": {
			Name:    "bars",
			TypeKey: "foos/bars",
			IdTuples: map[string]string{
				"foos": "{foosId}",
				"bars": "{barsId}",
			},
			OrderedCollectionIds: []string{"foos", "bars"},
		},
	}

	for k, expected := range testCases {
		actual, err := ParseRelativeName(k)
		if err != nil {
			t.Errorf("passing input '%s' returned error: %s", k, err)
		} else {
			checkRelativeName(t, k, expected, actual)
		}
	}
}

func checkRelativeName(t *testing.T, input string, expected, actual *RelativeResourceName) {
	if expected.TypeKey != actual.TypeKey {
		t.Errorf("Input '%s': expected output type key '%s', actual: '%s'", input, expected.TypeKey, actual.TypeKey)
	} else {
		if len(expected.IdTuples) != len(actual.IdTuples) {
			t.Errorf("Input '%s': IdMap length mismatch: Expected: '%+v', Actual: '%+v'", input, expected.IdTuples, actual.IdTuples)
		}
		for colId, expectedV := range expected.IdTuples {
			if expectedV != actual.IdTuples[colId] {
				t.Errorf("Input '%s': IdMap '%s' mismatch: expected: '%s', actual: '%s'", input, colId, expectedV, actual.IdTuples[colId])
			}
		}
		if len(expected.OrderedCollectionIds) != len(actual.OrderedCollectionIds) {
			t.Errorf("Input '%s': OrderedCollectionIds length mismatch: Expected: '%+v', Actual: '%+v'", input, expected.OrderedCollectionIds, actual.OrderedCollectionIds)
		}
		for i, expectedV := range expected.OrderedCollectionIds {
			if expectedV != actual.OrderedCollectionIds[i] {
				t.Errorf("Input '%s': OrderedCollectionIds['%d'] mismatch: expected: '%s', actual: '%s'", input, i, expectedV, actual.OrderedCollectionIds[i])
			}
		}
	}
}

func TestParseRelativeName_shouldError(t *testing.T) {
	testCases := []string{
		"",
		"/",
		"//",
		"projects",
		"//not.a.real.relname",
		"//cloudresourcemanager.googleapis.com/",
		"cloudresourcemanager.googleapis.com",
		"projects/X/global",
		"projects/X/global/serviceAccounts/",
		"projects//serviceAccounts/X@serviceaccounts.com",
	}

	for _, k := range testCases {
		relName, err := ParseRelativeName(k)
		if err == nil {
			t.Errorf("expected error for incorrect input '%s', actually got %v", k, relName)
		}
	}
}
