package gcpauth

import (
	"fmt"
	"github.com/fatih/structs"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"os"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	b := getTestBackend(t)

	credentialsJSON := os.Getenv(googleCredentialsEnv)
	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}
	credsMap := structs.New(creds).Map()

	configCreate := map[string]interface{}{
		"credentials":  credentialsJSON,
		"disable_tidy": true,
	}
	expectedCreate := map[string]interface{}{
		"credentials":  credsMap,
		"disable_tidy": true,
	}

	configUpdate := map[string]interface{}{
		"tidy_buffer": 100000,
	}
	expectedUpdate := map[string]interface{}{
		"credentials":  credsMap,
		"disable_tidy": true,
		"tidy_buffer":  time.Duration(100000) * time.Second,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		AcceptanceTest: true,
		PreCheck:       func() { testAccPreCheck(t) },
		Backend:        b,
		Steps: []logicaltest.TestStep{
			testConfigCreate(t, configCreate),
			testConfigRead(t, expectedCreate),
			testConfigUpdate(t, configUpdate),
			testConfigRead(t, expectedUpdate),
		},
	})
}

func testConfigCreate(t *testing.T, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      d,
	}
}

func testConfigUpdate(t *testing.T, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      d,
	}
}

func testConfigRead(t *testing.T, expected map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config",
		Check: func(resp *logical.Response) error {
			if resp.IsError() {
				return resp.Error()
			}

			for k, expectedV := range expected["credentials"].(map[string]interface{}) {
				actualV, ok := (resp.Data["credentials"]).(map[string]interface{})[k]
				if !ok {
					return fmt.Errorf("expected credentials field '%s' not found in actual result", k)
				} else if actualV != expectedV {
					return fmt.Errorf("credentials '%s' mismatch, expected %s but got %s", k, expectedV, actualV)
				}
			}

			expectedVal, ok := expected["disable_tidy"]
			if !ok {
				expectedVal = false
			}
			if resp.Data["disable_tidy"] != expectedVal.(bool) {
				return fmt.Errorf("disable_tidy mismatch, expected %s but got %s", expected["disable_tidy"], resp.Data["disable_tidy"])
			}

			expectedVal, ok = expected["tidy_buffer"]
			if !ok {
				expectedVal = time.Duration(0)
			}
			if resp.Data["tidy_buffer"].(time.Duration) != expectedVal.(time.Duration) {
				return fmt.Errorf("tidy_buffer mismatch, expected %s but got %s", expectedVal, resp.Data["tidy_buffer"])
			}

			if len(resp.Warnings) != 1 || resp.Warnings[0] != warningACLReadAccess {
				return errors.New("expected read access warning on response")
			}
			return nil
		},
	}
}
