## Unreleased

IMPROVEMENTS:
* Vault CLI now infers the service account email when running on Google Cloud [[GH-115](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/115)]
* Enable the Google service endpoints used by the underlying client to be customized [[GH-126](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/126)]

## 0.11.3

BUG FIXES:
* Fix token renewals when TokenPolicies have been configured [[GH-82](https://github.com/hashicorp/vault-plugin-auth-gcp/pull/82)]
