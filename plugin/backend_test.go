package gcpauth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	testAccPreCheck(t)

	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}

	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func testAccPreCheck(t *testing.T) {
	getTestCredentials(t)
}

func getTestCredentials(tb testing.TB) *gcputil.GcpCredentials {
	tb.Helper()

	credentialsJSON := os.Getenv(googleCredentialsEnv)
	if credentialsJSON == "" {
		tb.Fatalf("%s must be set to JSON string of valid Google credentials file", googleCredentialsEnv)
	}

	credentials, err := gcputil.Credentials(credentialsJSON)
	if err != nil {
		tb.Fatalf("valid Google credentials JSON could not be read from %s env variable: %v", googleCredentialsEnv, err)
	}

	return credentials
}
