export CGO_ENABLED?=0
export GO111MODULE?=on

default: build
.PHONY: default

verify: clean build fmt test cover coverage.html

build:
	CGO_ENABLED=$(CGO_ENABLED) GO111MODULE=$(GO111MODULE) go build -o vault-plugin-auth-gcp $(GOFLAGS) ./cmd/...
.PHONY: build

clean:
	rm -rf vault-plugin-auth-gcp* dist coverage.out coverage.html
.PHONY: clean

test:
	go test -short -parallel=40 ./...
.PHONY: test

vet:
	go vet ./...
.PHONY: vet

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	go fmt ./...
.PHONY: fmt

cover:
	CGO_ENABLED=1 go test -short -parallel=40 ./... -cover
.PHONY: cover

coverage.out:  | $(shell find . -name '*.go')
	go test -short -v -coverprofile=coverage.out ./...

coverage.html: | coverage.out
	go tool cover -html coverage.out -o coverage.html
