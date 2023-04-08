TOOL?=vault-gcp-auth-plugin
TEST?=$$(go list ./... | grep -v /vendor/)
EXTERNAL_TOOLS=
BUILD_TAGS?=${TOOL}
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
TEST_ARGS?=./...

PLUGIN_NAME?=$(shell command ls bin/)
PLUGIN_DIR?=$$GOPATH/vault-plugins
PLUGIN_PATH?=gcp

# bin generates the releaseable binaries for this plugin
.PHONY: bin
bin: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

.PHONY: default
default: dev

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin, except for quickdev which
# is only put into /bin/
.PHONY: quickdev
quickdev: generate
	@CGO_ENABLED=0 go build -i -tags='$(BUILD_TAGS)' -o bin/vault-gcp-auth-plugin
.PHONY: dev
dev: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
.PHONY: dev-dynamic
dev-dynamic: generate
	@CGO_ENABLED=1 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

.PHONY: testcompile
testcompile: fmtcheck generate
	@for pkg in $(TEST) ; do \
		go test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

.PHONY: test
test:
	@go test -short -parallel=40 ./... $(TESTARGS)

.PHONY: testacc
testacc:
	@export ACC_TEST_ENABLED=1 && go test -parallel=40 $(TEST) $(TESTARGS)
# generate runs `go generate` to build the dynamically generated
# source files.
.PHONY: generate
generate:
	@go generate $(go list ./... | grep -v /vendor/)

# bootstrap the build by downloading additional tools
.PHONY: bootstrap
bootstrap:
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofmt -w $(GOFMT_FILES)

.PHONY: mocks
mocks:
	mockgen -destination ${CURDIR}/plugin/mocks_test.go -package gcpauth github.com/hashicorp/vault/sdk/logical SystemView,Storage

.PHONY: setup-env
setup-env:
	cd bootstrap/terraform && terraform init && terraform apply -auto-approve

.PHONY: teardown-env
teardown-env:
	cd bootstrap/terraform && terraform init && terraform destroy -auto-approve

.PHONY: configure
configure: dev
	@./bootstrap/configure.sh \
	$(PLUGIN_DIR) \
	$(PLUGIN_NAME) \
	$(PLUGIN_PATH) \
	$(GOOGLE_TEST_CREDENTIALS) \
