# Acceptance Tests

The following BATs tests can be used to test basic functionality of the GCP Auth Engine.

## Prerequisites

* Clone this repository to your workstation
* [Bats Core installed](https://bats-core.readthedocs.io/en/stable/installation.html#homebrew)
* Docker
* Vault CLI installed
* GCP Project that has a service account w/ [required permissions](https://www.vaultproject.io/docs/auth/gcp#required-gcp-permissions)

### GCP Testing

First, set the following env variables from your GCP project 

* SERVICE_ACCOUNT_ID
* PATH_TO_CREDS env variable pointing to service account credentials JSON file
* GOOGLE_APPLICATION_CREDENTIALS
* GOOGLE_PROJECT
* GOOGLE_REGION

Next, set the following environment variable to specify the version of Vault to test


```bash
$ export VAULT_IMAGE='hashicorp/vault:1.9.0-rc1'
```

Finally, run the tests:

```bash
$ cd ./test/acceptance
$ bats gcp-auth.bat
```

