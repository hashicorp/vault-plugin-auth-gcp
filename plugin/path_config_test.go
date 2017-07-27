package gcpauth

import (
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"os"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	testAccPreCheck(t)
	b, reqStorage := getTestBackend(t)

	credentialsJSON := os.Getenv(googleCredentialsEnv)
	creds, err := getTestCredentials()
	if err != nil {
		t.Fatal(err)
	}
	credsMap := structs.New(creds).Map()

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials":  credentialsJSON,
		"disable_tidy": true,
	})

	testConfigRead(t, b, reqStorage, map[string]interface{}{
		"credentials":  credsMap,
		"disable_tidy": true,
	})

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"tidy_buffer": 100000,
	})

	testConfigRead(t, b, reqStorage, map[string]interface{}{
		"credentials":  credsMap,
		"disable_tidy": true,
		"tidy_buffer":  time.Duration(100000) * time.Second,
	})
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	for k, expectedV := range expected["credentials"].(map[string]interface{}) {
		actualV, ok := (resp.Data["credentials"]).(map[string]interface{})[k]
		if !ok {
			t.Fatalf("expected credentials field '%s' not found in actual result", k)
		} else if actualV != expectedV {
			t.Fatalf("credentials '%s' mismatch, expected %s but got %s", k, expectedV, actualV)
		}
	}

	expectedVal, ok := expected["disable_tidy"]
	if !ok {
		expectedVal = false
	}
	if resp.Data["disable_tidy"] != expectedVal.(bool) {
		t.Fatalf("disable_tidy mismatch, expected %s but got %s", expected["disable_tidy"], resp.Data["disable_tidy"])
	}

	expectedVal, ok = expected["tidy_buffer"]
	if !ok {
		expectedVal = time.Duration(0)
	}
	if resp.Data["tidy_buffer"].(time.Duration) != expectedVal.(time.Duration) {
		t.Fatalf("tidy_buffer mismatch, expected %s but got %s", expectedVal, resp.Data["tidy_buffer"])
	}

	if len(resp.Warnings) != 1 || resp.Warnings[0] != warningACLReadAccess {
		t.Fatal("expected read access warning on response")
	}
}
