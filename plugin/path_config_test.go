package gcpauth

import (
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
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

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials":  credentialsJSON,
		"disable_tidy": true,
	})

	expected := &gcpConfig{
		GcpCredentials: creds,
		DisableTidy:    true,
	}

	testConfigRead(t, b, reqStorage, expected)

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"disable_tidy": false,
		"tidy_buffer":  100000,
	})

	expected.DisableTidy = false
	expected.TidyBuffer = time.Duration(100000) * time.Second
	testConfigRead(t, b, reqStorage, expected)
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

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected *gcpConfig) {
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

	actual := &gcpConfig{}
	if err := mapstructure.WeakDecode(resp.Data, actual); err != nil {
		t.Fatalf("could not decode resp into gcpConfig: %s", err)
	}

	if actual.GcpCredentials != expected.GcpCredentials {
		t.Fatalf("credentials mismatch, expected:\n%v\naActual:\n%v\n", expected.GcpCredentials, actual.GcpCredentials)
	}

	if actual.TidyBuffer != expected.TidyBuffer {
		t.Fatalf("tidy buffer mismatch, expected:\n%v\naActual:\n%v\n", expected.TidyBuffer, actual.TidyBuffer)
	}

	if actual.DisableTidy != expected.DisableTidy {
		t.Fatalf("tidy buffer mismatch, expected:\n%v\naActual:\n%v\n", expected.DisableTidy, actual.DisableTidy)
	}

	if len(resp.Warnings) != 1 || resp.Warnings[0] != warningACLReadAccess {
		t.Fatal("expected read access warning on response")
	}
}
