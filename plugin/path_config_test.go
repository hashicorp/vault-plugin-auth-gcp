package gcpauth

import (
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	"testing"
)

func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	testConfigRead(t, b, reqStorage, nil)

	creds := map[string]interface{}{
		"client_email":   "testUser@google.com",
		"client_id":      "user123",
		"private_key_id": "privateKey123",
		"private_key":    "iAmAPrivateKey",
		"project_id":     "project123",
	}

	credJson, err := jsonutil.EncodeJSON(creds)
	if err != nil {
		t.Fatal(err)
	}

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credJson,
	})

	expected := map[string]interface{}{}
	for k, v := range creds {
		expected[k] = v
	}

	testConfigRead(t, b, reqStorage, expected)

	creds["project_id"] = "newProjectId123"
	credJson, err = jsonutil.EncodeJSON(creds)
	if err != nil {
		t.Fatal(err)
	}
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credJson,
	})

	expected["project_id"] = "newProjectId123"
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

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) {
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp == nil && expected == nil {
		return
	}

	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp.Data["client_email"] != expected["client_email"] {
		t.Fatalf("client_email mismatch, expected %s but actually %s", expected["client_email"], resp.Data["client_email"])
	}
	if resp.Data["client_id"] != expected["client_id"] {
		t.Fatalf("client_id mismatch, expected %s but actually %s", expected["client_id"], resp.Data["client_id"])
	}
	if resp.Data["private_key_id"] != expected["private_key_id"] {
		t.Fatalf("private_key_id mismatch, expected %s but actually %s", expected["private_key_id"], resp.Data["private_key_id"])
	}
	if resp.Data["private_key"] != expected["private_key"] {
		t.Fatalf("private_key mismatch, expected %s but actually %s", expected["private_key"], resp.Data["private_key"])
	}
	if resp.Data["project_id"] != expected["project_id"] {
		t.Fatalf("project_id mismatch, expected %s but actually %s", expected["project_id"], resp.Data["project_id"])
	}

	if len(resp.Warnings) != 1 || resp.Warnings[0] != warningACLReadAccess {
		t.Fatal("expected read access warning on response")
	}
}
