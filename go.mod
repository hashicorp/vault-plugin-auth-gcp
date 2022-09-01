module github.com/hashicorp/vault-plugin-auth-gcp

go 1.12

require (
	cloud.google.com/go/compute v1.6.1
	github.com/golang/mock v1.6.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-gcp-common v0.8.1-0.20220830160015-4bf6510b5976
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault/api v1.3.0
	github.com/hashicorp/vault/sdk v0.5.3
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/oauth2 v0.0.0-20220524215830-622c5d57e401
	google.golang.org/api v0.83.0
	gopkg.in/square/go-jose.v2 v2.6.0
)
