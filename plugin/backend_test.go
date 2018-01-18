package gcpauth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-gcp/plugin/util"
	"github.com/hashicorp/vault/helper/logformat"
	"github.com/hashicorp/vault/logical"
	"github.com/mgutz/logxi/v1"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	testAccPreCheck(t)

	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logformat.NewVaultLogger(log.LevelTrace),
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
	if _, err := getTestCredentials(); err != nil {
		t.Fatal(err)
	}
}

func getTestCredentials() (*util.GcpCredentials, error) {
	credentialsJSON := os.Getenv(googleCredentialsEnv)
	if credentialsJSON == "" {
		return nil, fmt.Errorf("%s must be set to JSON string of valid Google credentials file", googleCredentialsEnv)
	}

	credentials, err := util.Credentials(credentialsJSON)
	if err != nil {
		return nil, fmt.Errorf("valid Google credentials JSON could not be read from %s env variable: %v", googleCredentialsEnv, err)
	}
	return credentials, nil
}
