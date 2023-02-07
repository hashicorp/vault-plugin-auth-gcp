## Next

IMPROVEMENTS:

* Description [[GH-XXX](https://github.com/hashicorp/vault-plugin-auth-gcp)]

BUG FIXES: 

* Description [[GH-XXX](https://github.com/hashicorp/vault-plugin-auth-gcp)]

## v0.15.0

CHANGES:

* Changes user-agent header value to use correct Vault version information and include
  the plugin type and name in the comment section.

IMPROVEMENTS:

* Updates dependencies
  * `cloud.google.com/go/compute/metadata v0.2.3` [[GH-148](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/148)]
  * `github.com/hashicorp/go-hclog v1.4.0` [[GH-150](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/150)]
  * `github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7` [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]
  * `github.com/hashicorp/go-uuid v1.0.3` [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]
  * `github.com/hashicorp/vault/api v1.8.2` [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]
  * `github.com/hashicorp/vault/sdk v0.7.0` [[GH-157](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/157)]
  * `github.com/stretchr/testify v1.8.1` [[GH-143](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/143)]
  * `golang.org/x/oauth2 v0.4.0` [[GH-155](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/155)]
  * `google.golang.org/api v0.108.0` [[GH-156](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/156)]
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
