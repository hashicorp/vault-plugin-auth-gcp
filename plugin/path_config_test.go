package gcpauth

import (
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	"reflect"
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
	if resp != nil && resp.IsError() {
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

	if !reflect.DeepEqual(resp.Data, expected) {
		t.Fatalf("config mismatch, expected %v but actually %v", expected, resp.Data)
	}

	if len(resp.Warnings) != 1 || resp.Warnings[0] != warningACLReadAccess {
		t.Fatal("expected read access warning on response")
	}
}
