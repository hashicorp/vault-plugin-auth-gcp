package gcpauth

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/authmetadata"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	googleCredentialsEnv = "GOOGLE_TEST_CREDENTIALS"
)

func skipIfAccTestNotEnabled(t *testing.T) {
	if _, ok := os.LookupEnv("ACC_TEST_ENABLED"); !ok {
		t.Skip(fmt.Sprintf("Skipping accpetance test %s; ACC_TEST_ENABLED is not set.", t.Name()))
	}
}

func testBackend(tb testing.TB) (*GcpAuthBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}
	return b.(*GcpAuthBackend), config.StorageView
}

// testBackendWithCreds returns a new backend pre-populated with the
// credentials from the environment in the configuration.
func testBackendWithCreds(tb testing.TB) (*GcpAuthBackend, logical.Storage, *gcputil.GcpCredentials) {
	tb.Helper()

	creds := testCredentials(tb)

	b, storage := testBackend(tb)
	ctx := context.Background()

	entry, err := logical.StorageEntryJSON("config", &gcpConfig{
		Credentials:     creds,
		GCEAuthMetadata: authmetadata.NewHandler(gceAuthMetadataFields),
		IAMAuthMetadata: authmetadata.NewHandler(iamAuthMetadataFields),
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		tb.Fatal(err)
	}

	return b, storage, creds
}

func testCredentials(tb testing.TB) *gcputil.GcpCredentials {
	tb.Helper()

	var credsStr string
	credsEnv := os.Getenv("GOOGLE_TEST_CREDENTIALS")
	if credsEnv == "" {
		tb.Fatal("set GOOGLE_TEST_CREDENTIALS to JSON or path to JSON creds on disk to run integration tests")
	}

	// Attempt to read as file path; if invalid, assume given JSON value directly
	if _, err := os.Stat(credsEnv); err == nil {
		credsBytes, err := ioutil.ReadFile(credsEnv)
		if err != nil {
			tb.Fatalf("unable to read credentials file %s: %v", credsStr, err)
		}
		credsStr = string(credsBytes)
	} else {
		credsStr = credsEnv
	}

	creds, err := gcputil.Credentials(credsStr)
	if err != nil {
		tb.Fatalf("failed to parse GOOGLE_TEST_CREDENTIALS as JSON: %s", err)
	}

	return creds
}

// testFieldValidation verifies the given path has field validation.
func testFieldValidation(tb testing.TB, op logical.Operation, pth string) {
	tb.Helper()

	b, storage := testBackend(tb)
	ctx := context.Background()
	_, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: op,
		Path:      pth,
		Data: map[string]interface{}{
			"literally-never-a-key": true,
		},
	})
	if err == nil {
		tb.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		tb.Error(err)
	}
}
