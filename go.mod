module github.com/hashicorp/vault-plugin-auth-gcp

go 1.12

require (
	github.com/golang/mock v1.5.0
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-gcp-common v0.6.1-0.20210422195852-2fd33fd0a0e7
	github.com/hashicorp/go-hclog v0.12.0
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault/api v1.0.5-0.20200215224050-f6547fa8e820
	github.com/hashicorp/vault/sdk v0.1.14-0.20200427170607-03332aaf8d18
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/stretchr/testify v1.6.1
	golang.org/x/oauth2 v0.0.0-20210413134643-5e61552d6c78
	google.golang.org/api v0.45.0
	gopkg.in/square/go-jose.v2 v2.3.1
)
