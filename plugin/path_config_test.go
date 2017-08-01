package gcpauth

import (
	"github.com/hashicorp/vault-plugin-auth-gcp/util"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
	"testing"
)

func TestConfig(t *testing.T) {
	testAccPreCheck(t)
	b, reqStorage := getTestBackend(t)

	creds := util.GcpCredentials{
		ClientEmail:  "testUser@google.com",
		ClientId:     "user123",
		PrivateKeyId: "privateKey123",
		PrivateKey:   "iAmAPrivateKey",
		ProjectId:    "project123",
	}

	credJson, err := jsonutil.EncodeJSON(creds)
	if err != nil {
		t.Fatal(err)
	}
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credJson,
	})

	expected := &gcpConfig{
		GcpCredentials: creds,
	}
	testConfigRead(t, b, reqStorage, expected)

	creds.ProjectId = "newProjectId123"
	credJson, err = jsonutil.EncodeJSON(creds)
	if err != nil {
		t.Fatal(err)
	}
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credJson,
	})

	expected.ProjectId = "newProjectId123"
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

	if len(resp.Warnings) != 1 || resp.Warnings[0] != warningACLReadAccess {
		t.Fatal("expected read access warning on response")
	}
}
