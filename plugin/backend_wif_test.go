// Copyright IBM Corp. 2017, 2025
// SPDX-License-Identifier: MPL-2.0

package gcpauth

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeWIFConfig writes a minimal WIF (Workload Identity Federation) config
// to storage so that b.credentials() takes the externalaccount branch
// (i.e. identity_token_audience is set, no service-account JSON credentials).
func writeWIFConfig(t *testing.T, b *GcpAuthBackend, storage logical.Storage) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "config",
		Data: map[string]interface{}{
			"identity_token_ttl":      int64(30),
			"identity_token_audience": "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/vault-pool/providers/vault-provider",
			"service_account_email":   "vault-wif@test-project.iam.gserviceaccount.com",
		},
	})
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("writeWIFConfig: %s", resp.Error())
	}
}

// TestCredentials_WIF_UsesBackgroundContext verifies that WIF credentials and their
// underlying TokenSource are not tied to the lifetime of any individual request context.
//
// Credentials are cached for 30 minutes and reused across many requests. The TokenSource
// embedded in those credentials must remain valid for token refreshes long after the
// request that first created them has completed. This test confirms:
//  1. credentials() succeeds regardless of the calling context's cancellation state.
//  2. Subsequent calls within the cache TTL return the same cached pointer.
//  3. The TokenSource does not fail with context.Canceled when the original calling
//     context is cancelled — token refresh must be independent of request lifecycle.
//
// Note: TokenSource.Token() will fail with a network error in unit tests (no real
// GCP endpoint). The full end-to-end token-refresh path is covered by
// TestLogin_IAM/token_refresh_after_ctx_cancel (ACC_TEST_ENABLED=true).
func TestCredentials_WIF_UsesBackgroundContext(t *testing.T) {
	t.Parallel()

	b, storage := testBackend(t)
	writeWIFConfig(t, b, storage)

	// Use a cancellable context, as Vault's request handler does for each login call.
	reqCtx, cancel := context.WithCancel(context.Background())

	creds1, err := b.credentials(reqCtx, storage)
	require.NoError(t, err)
	require.NotNil(t, creds1)
	require.NotNil(t, creds1.TokenSource)

	// Cancel the context to simulate the request completing.
	cancel()

	// A subsequent call within the 30-min TTL must return the same cached object.
	creds2, err := b.credentials(context.Background(), storage)
	require.NoError(t, err)
	assert.Same(t, creds1, creds2,
		"credentials() must return the cached pointer within the TTL window")

	// Token refresh must succeed independently of the original calling context.
	// Any error must be a network/auth error — never a context cancellation.
	_, tokenErr := creds1.TokenSource.Token()
	if tokenErr != nil {
		assert.NotErrorIs(t, tokenErr, context.Canceled,
			"TokenSource.Token() must not fail with context.Canceled")
	}
}

// TestCredentials_CacheInvalidatedOnConfigWrite verifies that ClearCaches()
// causes credentials() to return a fresh *google.Credentials on the next call.
//
// ClearCaches is called by invalidate("config") on every config write, ensuring
// that changes such as a rotated service account or updated WIF audience take
// effect immediately rather than being served from cache for up to 30 minutes.
func TestCredentials_CacheInvalidatedOnConfigWrite(t *testing.T) {
	t.Parallel()

	b, storage := testBackend(t)
	writeWIFConfig(t, b, storage)

	ctx := context.Background()

	creds1, err := b.credentials(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, creds1)

	b.ClearCaches()

	creds2, err := b.credentials(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, creds2)

	assert.NotSame(t, creds1, creds2,
		"credentials() must return a new *google.Credentials after ClearCaches()")
}

// TestCredentials_ConcurrentAccess_NoRace verifies that the credential cache is
// safe for concurrent use: simultaneous reads and a mid-flight cache eviction must
// not produce data races or errors.
//
// Run with: go test -race ./plugin/... -run TestCredentials_ConcurrentAccess_NoRace
//
// The cache uses a double-check read-write lock. This test exercises the concurrent
// miss-and-refill path to confirm the lock correctly serialises all access.
func TestCredentials_ConcurrentAccess_NoRace(t *testing.T) {
	t.Parallel()

	b, storage := testBackend(t)
	writeWIFConfig(t, b, storage)

	ctx := context.Background()

	const goroutines = 30
	errCh := make(chan error, goroutines)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// One goroutine mid-flight evicts the cache to exercise the
			// concurrent miss-and-refill path.
			if idx == goroutines/2 {
				b.ClearCaches()
			}
			_, err := b.credentials(ctx, storage)
			errCh <- err
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		assert.NoError(t, err)
	}
}
