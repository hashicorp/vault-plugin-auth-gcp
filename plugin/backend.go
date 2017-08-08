package gcpauth

import (
	"fmt"
	"github.com/hashicorp/vault-plugin-auth-gcp/util"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/version"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"net/http"
	"runtime"
	"sync"
)

type GcpAuthBackend struct {
	*framework.Backend

	// OAuth scopes for generating HTTP and GCP service clients.
	oauthScopes []string

	// Locks for guarding service clients
	clientMutex sync.RWMutex

	// GCP service clients
	iamClient *iam.Service
}

// Factory returns a new backend as logical.Backend.
func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *GcpAuthBackend {
	b := &GcpAuthBackend{
		oauthScopes: []string{
			iam.CloudPlatformScope,
		},
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathLoginRenew,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathLogin(b),
			},
			pathsRole(b),
		),
	}
	return b
}

// Initialize attempts to create GCP clients from stored config.
func (b *GcpAuthBackend) initClients(s logical.Storage) (err error) {
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	config, err := b.config(s)
	if err != nil {
		return err
	}

	var httpClient *http.Client
	if config == nil || len(config.PrivateKey) == 0 {
		// Use Application Default Credentials
		httpClient, err = google.DefaultClient(oauth2.NoContext, b.oauthScopes...)
		if err != nil {
			return fmt.Errorf("credentials were not configured and fallback to application default credentials failed: %s", err)
		}
	} else {
		httpClient, err = util.GetHttpClient(&config.GcpCredentials, b.oauthScopes...)
		if err != nil {
			return err
		}
	}

	userAgentStr := fmt.Sprintf("(%s %s) Vault/%s", runtime.GOOS, runtime.GOARCH, version.GetVersion().FullVersionNumber(true))

	b.iamClient, err = iam.New(httpClient)
	if err != nil {
		b.Close()
		return err
	}
	b.iamClient.UserAgent = userAgentStr

	return nil
}

// Close deletes created GCP clients in backend.
func (b *GcpAuthBackend) Close() {
	b.iamClient = nil
}

const backendHelp = `
The GCP credential provider allows authentication for Google Cloud Platform entities.
Currently supports authentication for:

IAM service accounts:
	IAM service accounts provide a signed JSON Web Token (JWT), signed by
	calling GCP APIs directly or via the Vault CL helper. If successful,
	Vault will also return a client nonce that is required as the 'jti'
	field for all subsequent logins by this instance.
`
