## Next

BUG FIXES:
* Forward Performance Secondary Requests when configuring root credentials [GH-228](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/228)

## v0.20.1

IMPROVEMENTS:
* Update dependencies:
  * `golang.org/x/crypto` v0.33.0 -> v0.35.0
  * `github.com/go-jose/go-jose/v4` v4.0.4 -> v4.0.5
  * `github.com/hashicorp/vault/sdk` v0.15.0 -> v0.15.2
  * `golang.org/x/oauth2` v0.26.0 -> v0.27.0

## v0.20.0

IMPROVEMENTS:
* Add support for Vault Enterprise automated root rotation
* Add config/rotate-root endpoint
* Update dependencies:
  * `github.com/hashicorp/vault/api` v1.15.0 -> v1.16.0
  * `golang.org/x/oauth2` v0.24.0 -> v0.26.0
  * `google.golang.org/api` v0.214.0 -> v0.221.0


## v0.19.0

IMPROVEMENTS:
* Updated dependencies:
   * `cloud.google.com/go/compute/metadata` v0.3.0 -> v0.5.0
   * `github.com/go-jose/go-jose/v4` v4.0.1 -> v4.0.4
   * `github.com/hashicorp/vault/api` v1.13.0 -> v1.15.0
   * `github.com/hashicorp/vault/sdk` v0.12.0 -> v0.14.0
   * `golang.org/x/oauth2` v0.19.0 -> v0.23.0
   * `google.golang.org/api` v0.177.0 -> v0.196.0

## v0.18.0

IMPROVEMENTS:
* Added support for Workload Identity Federation [GH-204](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/204)
* Updated dependencies:
  * `google.golang.org/api` v0.172.0 -> v0.177.0
  * `google.golang.org/genproto/googleapis/rpc` v0.0.0-20240318140521-94a12d6c2237 -> v0.0.0-20240429193739-8cf5692501f6
  * `google.golang.org/grpc`  v1.62.1 -> v1.63.2
  * `google.golang.org/protobuf` v1.33.0 -> v1.34.0

## v0.17.0

IMPROVEMENTS:
* Remove `gopkg.in/square/go-jose.v2` dependency [GH-203](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/203)

## v0.16.3

IMPROVEMENTS:

* Updated dependencies:
   * `cloud.google.com/go/compute/metadata` v0.2.3 -> v0.3.0
   * `github.com/hashicorp/go-hclog` v1.6.2 -> v1.6.3
   * `github.com/hashicorp/vault/api` v1.11.0 -> v1.13.0
   * `github.com/hashicorp/vault/sdk` v0.10.2 -> v0.12.0
   * `github.com/stretchr/testify` v1.8.4 -> v1.9.0
   * `golang.org/x/oauth2` v0.16.0 -> v0.19.0
   * `google.golang.org/api` v0.161.0 -> v0.172.0
* Upgrade `gopkg.in/square/go-jose.v2` and `github.com/go-jose/go-jose/v3` to `github.com/go-jose/go-jose/v4` 4.0.1: [GH-202](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/202), [GH-203](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/203)
* Bump `google.golang.org/protobuf` from 1.32.0 to 1.33.0: [GH-197](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/197)
* Bump `github.com/docker/docker` from 24.0.7+incompatible to 24.0.9+incompatible: [GH-198](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/198)
* Bump `golang.org/x/net` from 0.22.0 to 0.24.0: [GH-201](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/201)

## v0.16.2

IMPROVEMENTS:

* Updated dependencies:
  * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
  * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.7 -> v0.1.8
  * `github.com/hashicorp/vault/api` v1.9.2 -> v1.11.0
  * `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.2
  * `golang.org/x/oauth2` v0.11.0 -> v0.16.0
  * `google.golang.org/api` v0.138.0 -> v0.161.0
* Bump golang.org/x/crypto from 0.12.0 to 0.17.0: [GH-191](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/191)
* Bump github.com/go-jose/go-jose/v3 from 3.0.0 to 3.0.1: [GH-188](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/188)
* Bump google.golang.org/grpc from 1.57.0 to 1.57.1: [GH-187](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/187)
* Bump golang.org/x/net from 0.14.0 to 0.17.0: [GH-186](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/186)

## v0.16.1

IMPROVEMENTS:

* Updated dependencies:
  * `github.com/hashicorp/vault/api` v1.9.1 -> v1.9.2
  * `github.com/hashicorp/vault/sdk` v0.9.0 -> v0.9.2
  * `github.com/stretchr/testify` v1.8.3 -> v1.8.4
  * `golang.org/x/oauth2` v0.8.0 -> v0.11.0
  * `google.golang.org/api` v0.124.0 -> v0.138.0

## v0.16.0

IMPROVEMENTS:

* Enable plugin multiplexing [[GH-164](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/164)]
* Add display attributes for OpenAPI OperationID's [[GH-172](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/172)]
* Updated dependencies:
  * `github.com/hashicorp/vault/sdk` v0.9.0 [[GH-172](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/172)]
  * [GH-178](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/178):
   * `github.com/hashicorp/go-hclog` v1.4.0 -> v1.5.0
   * `github.com/hashicorp/vault/api` v1.8.3 -> v1.9.1
   * `github.com/stretchr/testify` v1.8.1 -> v1.8.3
   * `golang.org/x/oauth2` v0.4.0 -> v0.8.0
   * `google.golang.org/api` v0.109.0 -> v0.124.0

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
