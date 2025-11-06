//go:build fips

package gcpauth

// The above directive will only include this file in the build when the "fips" tag is specified.
// Ex. CGO_ENABLED=1 GOEXPERIMENT=boringcrypto go build -tags=fips ./cmd/...
// If this file is included without using boringcrypto the build will fail.
//
// See this doc for enabling FIPS for go workloads https://datadoghq.atlassian.net/wiki/spaces/PPLAT/pages/4403363932/Golang+FIPS+Builds

//
// Ensure any TLS connection is made through FIPS compliant algorithms
// cf: https://github.com/golang/go/blob/master/src/crypto/tls/fipsonly/fipsonly.go
//
import _ "crypto/tls/fipsonly"
