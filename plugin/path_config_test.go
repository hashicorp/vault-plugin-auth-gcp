package gcpauth

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
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

	expected := map[string]interface{}{
		"client_email":          creds["client_email"],
		"client_id":             creds["client_id"],
		"private_key_id":        creds["private_key_id"],
		"project_id":            creds["project_id"],
		"google_certs_endpoint": "",
	}

	testConfigRead(t, b, reqStorage, expected)
	creds["project_id"] = "newProjectId123"
	credJson, err = jsonutil.EncodeJSON(creds)
	if err != nil {
		t.Fatal(err)
	}
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials":           credJson,
		"google_certs_endpoint": "https://www.fakecredsendpoint.com/",
	})

	expected["project_id"] = "newProjectId123"
	expected["google_certs_endpoint"] = "https://www.fakecredsendpoint.com/"
	testConfigRead(t, b, reqStorage, expected)
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
}
