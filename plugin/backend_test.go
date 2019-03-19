package gcpauth

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/logical"
)

const (
	googleCredentialsEnv = "GOOGLE_CREDENTIALS"
)

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
		Credentials: creds,
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

	creds := os.Getenv(googleCredentialsEnv)
	if creds == "" {
		tb.Fatalf("%s must be set to JSON string of valid Google credentials file", googleCredentialsEnv)
	}

	credentials, err := gcputil.Credentials(creds)
	if err != nil {
		tb.Fatalf("valid Google credentials JSON could not be read from %s env variable: %v", googleCredentialsEnv, err)
	}

	return credentials
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
