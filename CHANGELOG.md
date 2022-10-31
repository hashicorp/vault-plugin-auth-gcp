## Next

IMPROVEMENTS:

* Updates dependencies: `cloud.google.com/go/compute/metadata v0.2.1`, `github.com/hashicorp/go-hclog v1.3.1`, `github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7`
, `github.com/hashicorp/go-uuid v1.0.3`, `github.com/hashicorp/vault/api v1.8.2`, `github.com/hashicorp/vault/sdk v0.6.1`, 
`github.com/stretchr/testify v1.8.1`, `golang.org/x/oauth2 v0.1.0`, `google.golang.org/api v0.101.0` [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]
* Upgraded to go 1.19 [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]
* Added utility scripts for local setup [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]

## v0.14.0

IMPROVEMENTS:

* Updates dependencies: `google.golang.org/api@v0.83.0`, `github.com/hashicorp/go-gcp-common@v0.8.0` [[GH-130](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/130)]
* Enables GCP roles to be compatible with Vault's role based quotas [[GH-135](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/135)].
* Add support for GCE regional instance groups [[GH-84](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/84)]

## v0.13.2

BUG FIXES:

* Fixes the ability to reset the configuration's credentials to use application default credentials [[GH-132](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/132)]

## v0.13.0

IMPROVEMENTS:
* Vault CLI now infers the service account email when running on Google Cloud [[GH-115](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/115)]
* Enable the Google service endpoints used by the underlying client to be customized [[GH-126](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/126)]

## v0.12.2

BUG FIXES:

* Fixes the ability to reset the configuration's credentials to use application default credentials [[GH-132](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/132)]

## v0.11.3

BUG FIXES:
* Fix token renewals when TokenPolicies have been configured [[GH-82](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/82)]
