package gcpauth

import (
	"context"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"net/http"
)

type GcpAuthBackend struct {
	*framework.Backend

	// OAuth scopes for generating HTTP and GCP service clients.
	oauthScopes []string
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *GcpAuthBackend {
	b := &GcpAuthBackend{
		oauthScopes: []string{
			iam.CloudPlatformScope,
			compute.ComputeReadonlyScope,
			cloudresourcemanager.CloudPlatformScope,
		},
	}

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config",
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

func (b *GcpAuthBackend) httpClient(ctx context.Context, s logical.Storage) (*http.Client, error) {
	config, err := b.config(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("credentials were not configured and fallback to application default credentials failed: %v", err)
	}

	var httpClient *http.Client
	if config == nil || config.Credentials == nil {
		_, tknSrc, err := gcputil.FindCredentials("", ctx, b.oauthScopes...)
		if err != nil {
			return nil, errwrap.Wrapf("credentials were not configured, could not obtain application default credentials: {{err}}", err)
		}

		cleanCtx := context.WithValue(ctx, oauth2.HTTPClient, cleanhttp.DefaultClient())
		httpClient = oauth2.NewClient(cleanCtx, tknSrc)
	} else {
		conf := jwt.Config{
			Email:      config.Credentials.ClientEmail,
			PrivateKey: []byte(config.Credentials.PrivateKey),
			Scopes:     b.oauthScopes,
			TokenURL:   "https://accounts.google.com/o/oauth2/token",
		}
		ctx := context.WithValue(ctx, oauth2.HTTPClient, cleanhttp.DefaultClient())
		client := conf.Client(ctx)
		return client, nil
		httpClient, err = gcputil.GetHttpClient(config.Credentials, b.oauthScopes...)
		if err != nil {
			return nil, errwrap.Wrapf("could not create HTTP client for given config credentials: {{err}}", err)
		}
	}
	return httpClient, nil
}

const backendHelp = `
The GCP backend plugin allows authentication for Google Cloud Platform entities.
Currently, it supports authentication for:

* IAM Service Accounts:
	IAM service accounts provide a signed JSON Web Token (JWT), signed by
	calling GCP APIs directly or via the Vault CL helper.

* GCE VM Instances:
	GCE provide a signed instance metadata JSON Web Token (JWT), obtained from the
	GCE instance metadata server  (http://metadata.google.internal/computeMetadata/v1/instance).
	Using the /service-accounts/<service-account-name>/identity	endpoint, the instance
	can obtain this JWT and pass it to Vault on login.
`
