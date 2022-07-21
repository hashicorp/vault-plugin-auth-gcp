## Next

BUG FIXES:

* Fixes the ability to reset the configuration's credentials to use application default credentials [[GH-132](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/132)]

IMPROVEMENTS:

* Updates dependencies: `google.golang.org/api@v0.83.0`, `github.com/hashicorp/go-gcp-common@v0.8.0` [[GH-130](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/130)]
* Enables GCP roles to be compatible with Vault's role based quotas [[GH-135](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/135)].

## v0.13.0

IMPROVEMENTS:
* Vault CLI now infers the service account email when running on Google Cloud [[GH-115](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/115)]
* Enable the Google service endpoints used by the underlying client to be customized [[GH-126](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/126)]

## v0.11.3

BUG FIXES:
* Fix token renewals when TokenPolicies have been configured [[GH-82](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/82)]
