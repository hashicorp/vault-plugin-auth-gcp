module github.com/hashicorp/vault-plugin-auth-gcp

go 1.12

require (
	github.com/golang/mock v1.6.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-gcp-common v0.7.0
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault/api v1.3.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/oauth2 v0.0.0-20211028175245-ba495a64dcb5
	google.golang.org/api v0.60.0
	gopkg.in/square/go-jose.v2 v2.6.0
)
