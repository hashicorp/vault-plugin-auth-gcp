Vault Plugin: Google Cloud Platform Auth Backend
------------------------------------------------
This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for various GCP entities to authenticate with Vault.

Currently, this plugin supports login for:
- IAM service accounts

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).


Getting Started & Documentation
-------------------------------

All documentation is available on the Vault website under the
[GCP Auth section](https://www.vaultproject.io/docs/auth/gcp.html).

See documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html)
to learn more specifically about plugins.

=========

-	Website: https://www.vaultproject.io
-   Main Project: https://www.github.com/hashicorp/vault
-	Announcement list: [Google Groups](https://groups.google.com/group/hashicorp-announce)
-	Discussion list: [Google Groups](https://groups.google.com/group/vault-tool)


Developing
----------

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine
(version 1.8+ is *required*).

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).
Next, clone this repository into
`$GOPATH/src/github.com/hashicorp/vault-gcp-auth-plugin`.
You can then download any required build tools by bootstrapping your
environment:

```sh
$ make bootstrap
...
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders:

```sh
$ make dev
...
$ bin/vault
...
```

To run tests, type `make test`. Note: this requires Docker to be installed. If
this exits with exit status 0, then everything is working!

```sh
$ make test
...
```

If you're developing a specific package, you can run tests for just that
package by specifying the `TEST` variable. For example below, only
`vault` package tests will be run.

```sh
$ make test TEST=./vault
...
```

### Acceptance Tests

This plugin  has comprehensive [acceptance tests](https://en.wikipedia.org/wiki/Acceptance_testing)
covering most of the features of this auth backend.

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the acceptance tests.

**Warning:** The acceptance tests create/destroy/modify *real resources*, which
may incur real costs in some cases. In the presence of a bug, it is technically
possible that broken backends could leave dangling data behind. Therefore,
please run the acceptance tests at your own risk. At the very least,
we recommend running them in their own private account for whatever backend
you're testing.

To run the acceptance tests, invoke `make testacc`:

```sh
$ make testacc TEST=./builtin/logical/consul
...
```

The `TEST` variable is required, and you should specify the folder where the
backend is. The `TESTARGS` variable is recommended to filter down to a specific
resource to test, since testing all of them at once can sometimes take a very
long time.

Acceptance tests typically require other environment variables to be set for
things such as access keys. The test itself should error early and tell
you what to set, so it is not documented here.
