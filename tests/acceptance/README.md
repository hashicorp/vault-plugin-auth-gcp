# Acceptance Tests

The following BATs tests can be used to test basic functionality of the GCP Auth Engine.

## Prerequisites

* Clone this repository to your workstation
* [Bats Core installed](https://bats-core.readthedocs.io/en/stable/installation.html#homebrew)
* Docker
* Vault CLI installed
* GCP Project that has a service account w/ [required permissions](https://www.vaultproject.io/docs/auth/gcp#required-gcp-permissions)

### GCP Testing

The following are the environment variables that need to be set for the BATs scripts and the Go SDK

* SERVICE_ACCOUNT_ID
* GOOGLE_APPLICATION_CREDENTIALS (path to the credentials file)
* GOOGLE_CLOUD_PROJECT (ID of the Google Project, used internally by Go SDK)
* GOOGLE_REGION


Run the tests:

```bash
$ cd ./tests/acceptance
$ bats gcp-auth.bats
```

