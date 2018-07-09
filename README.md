# Vault Plugin: Google Cloud Platform Auth Backend

This is a standalone backend plugin for use with [HashiCorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for various GCP entities to authenticate with Vault.
This is currently included in Vault distributions.

Currently, this plugin supports login for:

- IAM service accounts
- GCE Instances

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [GCP Auth BE Docs](https://www.vaultproject.io/docs/auth/gcp.html)
- [Vault Github](https://www.github.com/hashicorp/vault)
- [General Announcement List](https://groups.google.com/forum/#!forum/hashicorp-announce)
- [Discussion List](https://groups.google.com/forum/#!forum/vault-tool)


## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

### Usage

Please see [documentation for the plugin](https://www.vaultproject.io/docs/auth/gcp.html)
on the Vault website.

This plugin is currently built into Vault and by default is accessed
at `auth/gcp`. To enable this in a running Vault server:

```sh
$ vault auth enable gcp
Success! Enabled gcp auth method at: gcp/
```

To see all the supported paths, see the [GCP auth backend docs](https://www.vaultproject.io/docs/auth/gcp.html).

## Developing

Please note that local development is only required if you plan to contribute or
compile this plugin yourself. This plugin is automatically bundled in Vault
installations and is available by default. You do not need to compile it
yourself unless you intend to modify it.

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine (version 1.8+ is
*required*).

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).
Next, clone this repository into your `GOPATH`:

```sh
$ mkdir -p $GOPATH/src/github.com/hashicorp
$ git clone https://github.com/hashicorp/vault-plugin-auth-gcp $GOPATH/src/github.com/hashicorp/
$ cd vault-plugin-auth-gcp
```

You can then download any required build tools by bootstrapping your
environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

For local development, use Vault's "dev" mode for fast setup:

```sh
$ vault server -dev -dev-plugin-dir="$(pwd)/bin"
```

The plugin will automatically be added to the catalog with the name
"vault-plugin-auth-gcp". Run the following command to enable this new auth
method as a plugin:

```sh
$ vault auth enable -plugin-name="vault-plugin-auth-gcp" -path="gcp" plugin
Success! Enabled vault-plugin-auth-gcp plugin at: gcp/
```

#### Tests

This plugin has comprehensive [acceptance tests](https://en.wikipedia.org/wiki/Acceptance_testing)
covering most of the features of this auth backend.

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the acceptance tests.

Acceptance tests typically require other environment variables to be set for
things such as access keys. The test itself should error early and tell
you what to set, so it is not documented here.

**Warning:** The acceptance tests create/destroy/modify *real resources*,
which may incur real costs in some cases. In the presence of a bug,
it is technically possible that broken backends could leave dangling
data behind. Therefore, please run the acceptance tests at your own risk.
At the very least, we recommend running them in their own private
account for whatever backend you're testing.

To run the acceptance tests, you will need a GCP IAM service account with
project.viewer and serviceaccount.admin permission. You can generate one from
the Google Cloud Console. Save this file locally and export its contents as an
environment variable:

```sh
$ export GOOGLE_CREDENTIALS="$(cat my-credentials.sh)"
```

To run the acceptance tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```
