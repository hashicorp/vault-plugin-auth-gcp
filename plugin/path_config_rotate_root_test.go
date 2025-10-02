// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func TestConfigRotateRootUpdate(t *testing.T) {
	t.Parallel()

	t.Run("no_configuration", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if exp, act := "configuration does not have credentials", err.Error(); !strings.Contains(act, exp) {
			t.Errorf("expected %q to contain %q", act, exp)
		}
	})

	t.Run("config_with_no_credentials", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON("config", &gcpConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		_, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if exp, act := "does not have credentials", err.Error(); !strings.Contains(act, exp) {
			t.Errorf("expected %q to contain %q", act, exp)
		}
	})

	t.Run("config_with_invalid_credentials", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON("config", &gcpConfig{
			Credentials: &gcputil.GcpCredentials{
				ClientEmail:  "user@test.com",
				ClientId:     "user",
				PrivateKeyId: "key_id",
				PrivateKey:   "key",
				ProjectId:    "project",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		_, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if exp, act := "failed to create new key", err.Error(); !strings.Contains(act, exp) {
			t.Errorf("expected %q to contain %q", act, exp)
		}
	})

	t.Run("rotate", func(t *testing.T) {
		t.Parallel()

		if testing.Short() {
			t.Skip("skipping integration test (short)")
		}

		ctx := context.Background()
		b, storage := testBackend(t)

		// Get user-supplied credentials
		_, creds := getTestCredentials(t)
		client, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
		if err != nil {
			t.Fatal(err)
		}

		// Create IAM client
		iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			t.Fatal(err)
		}

		// Create a new key, since this endpoint will revoke the key given.
		saName := "projects/-/serviceAccounts/" + creds.ClientEmail
		newKey, err := iamAdmin.Projects.ServiceAccounts.Keys.
			Create(saName, &iam.CreateServiceAccountKeyRequest{
				KeyAlgorithm:   keyAlgorithmRSA2k,
				PrivateKeyType: privateKeyTypeJson,
			}).
			Context(ctx).
			Do()
		if err != nil {
			t.Fatal(err)
		}

		// Base64-decode the private key data (it's the JSON file)
		newCredsJSON, err := base64.StdEncoding.DecodeString(newKey.PrivateKeyData)
		if err != nil {
			t.Fatal(err)
		}

		// Parse new creds
		newCreds, err := gcputil.Credentials(string(newCredsJSON))
		if err != nil {
			t.Fatal(err)
		}

		// If we made it this far, schedule a cleanup of the key we just created.
		defer tryCleanupKey(t, iamAdmin, newKey.Name)

		// Set config to the key
		entry, err := logical.StorageEntryJSON("config", &gcpConfig{
			Credentials: newCreds,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}
		b.ClearCaches()

		// Rotate the key - retrying until success because of new key eventual consistency
		rawResp, err := retryTestFunc(func() (interface{}, error) {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/rotate-root",
				Storage:   storage,
			})
			if err != nil {
				return resp, err
			}
			if resp != nil && resp.IsError() {
				return resp, resp.Error()
			}
			return resp, err
		}, 10)
		if err != nil {
			t.Fatal(err)
		}
		resp := rawResp.(*logical.Response)

		privateKeyId := resp.Data["private_key_id"]
		if privateKeyId == "" {
			t.Errorf("missing private_key_id")
		}

		// Make sure we delete the stored key, whether it was rotated or not (retry will not error)
		defer tryCleanupKey(t, iamAdmin, fmt.Sprintf(gcputil.ServiceAccountKeyTemplate,
			newCreds.ProjectId,
			newCreds.ClientEmail,
			privateKeyId))

		if privateKeyId == newCreds.PrivateKeyId {
			t.Errorf("creds were not rotated")
		}
	})
}

func tryCleanupKey(t *testing.T, iamAdmin *iam.Service, keyName string) {
	_, err := iamAdmin.Projects.ServiceAccounts.Keys.Delete(keyName).Do()
	if err != nil && !isGoogleAccountKeyNotFoundErr(err) {
		t.Logf("WARNING: failed to delete key created for test, clean up manually: %v", err)
	}
}

func retryTestFunc(f func() (interface{}, error), retries int) (interface{}, error) {
	var err error
	var value interface{}
	for i := 0; i < retries; i++ {
		if value, err = f(); err == nil {
			return value, nil
		}
		log.Printf("[DEBUG] test check failed with error %v (attempt %d), sleeping one second before trying again", err, i)
		time.Sleep(time.Second)
	}
	return value, err
}

func getTestCredentials(tb testing.TB) (string, *gcputil.GcpCredentials) {
	tb.Helper()

	if testing.Short() {
		tb.Skip("skipping integration test (short)")
	}

	var credsStr string
	credsEnv := os.Getenv("GOOGLE_TEST_CREDENTIALS")
	if credsEnv == "" {
		tb.Fatal("set GOOGLE_TEST_CREDENTIALS to JSON or path to JSON creds on disk to run integration tests")
	}

	// Attempt to read as file path; if invalid, assume given JSON value directly
	if _, err := os.Stat(credsEnv); err == nil {
		credsBytes, err := ioutil.ReadFile(credsEnv)
		if err != nil {
			tb.Fatalf("unable to read credentials file %s: %v", credsStr, err)
		}
		credsStr = string(credsBytes)
	} else {
		credsStr = credsEnv
	}

	creds, err := gcputil.Credentials(credsStr)
	if err != nil {
		tb.Fatalf("failed to parse GOOGLE_TEST_CREDENTIALS as JSON: %s", err)
	}
	return credsStr, creds
}

func isGoogleAccountNotFoundErr(err error) bool {
	return isGoogleApiErrorWithCodes(err, 404)
}

func isGoogleAccountKeyNotFoundErr(err error) bool {
	return isGoogleApiErrorWithCodes(err, 403, 404)
}

func isGoogleAccountUnauthorizedErr(err error) bool {
	return isGoogleApiErrorWithCodes(err, 403)
}

func isGoogleApiErrorWithCodes(err error, validErrCodes ...int) bool {
	if err == nil {
		return false
	}

	gErr, ok := err.(*googleapi.Error)
	if !ok {
		wrapErrV := errwrap.GetType(err, &googleapi.Error{})
		if wrapErrV == nil {
			return false
		}
		gErr = wrapErrV.(*googleapi.Error)
	}

	for _, code := range validErrCodes {
		if gErr.Code == code {
			return true
		}
	}

	return false
}
