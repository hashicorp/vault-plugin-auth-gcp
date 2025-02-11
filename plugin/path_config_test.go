// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpauth

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/authmetadata"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
	rotation "github.com/hashicorp/vault/sdk/rotation"
)

func TestBackend_PathConfigRead(t *testing.T) {
	t.Run("field_validation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, logical.ReadOperation, "config")
	})

	t.Run("not_exist", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)
		ctx := context.Background()
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		// These fields are always returned on read
		// 2 Metadata response fields
		// 2 Identity Token fields
		if len(resp.Data) != 4 {
			t.Fatal("expected 4 fields")
		}
		expectedResp := &logical.Response{
			Data: map[string]interface{}{
				"iam_metadata": []string{
					"project_id",
					"role",
					"service_account_id",
					"service_account_email",
				},
				"gce_metadata": []string{
					"instance_creation_timestamp",
					"instance_id",
					"instance_name",
					"project_id",
					"project_number",
					"role",
					"service_account_id",
					"service_account_email",
					"zone",
				},
				"identity_token_audience": "",
				"identity_token_ttl":      int64(0),
			},
		}
		if !reflect.DeepEqual(resp, expectedResp) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp, expectedResp)
		}
	})

	t.Run("exist", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)
		ctx := context.Background()

		entry, err := logical.StorageEntryJSON("config", &gcpConfig{
			Credentials: &gcputil.GcpCredentials{
				ClientEmail:  "user@test.com",
				ClientId:     "user",
				PrivateKeyId: "key_id",
				PrivateKey:   "key",
				ProjectId:    "project",
			},
			IAMAliasType:          defaultIAMAlias,
			IAMAuthMetadata:       authmetadata.NewHandler(iamAuthMetadataFields),
			GCEAliasType:          defaultGCEAlias,
			GCEAuthMetadata:       authmetadata.NewHandler(gceAuthMetadataFields),
			APICustomEndpoint:     "https://www.example.com",
			IAMCustomEndpoint:     "https://iam.example.com",
			CRMCustomEndpoint:     "https://cloudresourcemanager.example.com",
			ComputeCustomEndpoint: "https://compute.example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		if err != nil {
			t.Fatal(err)
		}

		expectedData := map[string]interface{}{
			"client_email":   "user@test.com",
			"client_id":      "user",
			"private_key_id": "key_id",
			"project_id":     "project",
			"iam_alias":      defaultIAMAlias,
			"iam_metadata": []string{
				"project_id",
				"role",
				"service_account_id",
				"service_account_email",
			},
			"gce_alias": defaultGCEAlias,
			"gce_metadata": []string{
				"instance_creation_timestamp",
				"instance_id",
				"instance_name",
				"project_id",
				"project_number",
				"role",
				"service_account_id",
				"service_account_email",
				"zone",
			},
			"custom_endpoint": map[string]string{
				"api":     "https://www.example.com",
				"iam":     "https://iam.example.com",
				"crm":     "https://cloudresourcemanager.example.com",
				"compute": "https://compute.example.com",
			},
			"identity_token_audience":    "",
			"identity_token_ttl":         int64(0),
			"disable_automated_rotation": false,
			"rotation_period":            0,
			"rotation_window":            0,
			"rotation_schedule":          "",
		}

		if !reflect.DeepEqual(resp.Data, expectedData) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp.Data, expectedData)
		}
	})
}

func TestBackend_PathConfigWrite(t *testing.T) {
	t.Run("field_validation", func(t *testing.T) {
		testFieldValidation(t, logical.UpdateOperation, "config")
	})

	t.Run("not_exist", func(t *testing.T) {
		b, storage := testBackend(t)
		ctx := context.Background()
		if _, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]interface{}{
				"credentials": `{
				  "project_id": "project_id",
				  "private_key_id": "key_id",
				  "private_key": "key",
				  "client_email": "user@test.com",
				  "client_id": "client_id"
				}`,
				"custom_endpoint": map[string]string{
					"iam":     "https://example-iam.com",
					"api":     "https://example-api.com",
					"crm":     "https://example-crm.com",
					"compute": "https://example-compute.com",
				},
			},
		}); err != nil {
			t.Fatal(err)
		}

		config, err := b.config(ctx, storage)
		if err != nil {
			t.Fatal(err)
		}

		creds := config.Credentials
		if creds == nil {
			t.Fatal("expected credentials to exist")
		}

		if v, exp := creds.ClientEmail, "user@test.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.ClientId, "client_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.PrivateKeyId, "key_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.PrivateKey, "key"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.ProjectId, "project_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := config.IAMCustomEndpoint, "https://example-iam.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
		if v, exp := config.APICustomEndpoint, "https://example-api.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
		if v, exp := config.CRMCustomEndpoint, "https://example-crm.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
		if v, exp := config.ComputeCustomEndpoint, "https://example-compute.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})

	t.Run("bad custom endpoint", func(t *testing.T) {
		b, storage := testBackend(t)
		ctx := context.Background()
		if _, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]interface{}{
				"custom_endpoint": map[string]string{
					"iam":       "https://example-iam.com",
					"not-valid": "https://example-iam-creds.com",
				},
			},
		}); err == nil {
			t.Fatal("expected error but got nil")
		}
	})

	t.Run("exist", func(t *testing.T) {
		b, storage := testBackend(t)
		ctx := context.Background()

		entry, err := logical.StorageEntryJSON("config", &gcpConfig{
			Credentials: &gcputil.GcpCredentials{
				ClientEmail:  "user@test.com",
				ClientId:     "user",
				PrivateKeyId: "key_id",
				PrivateKey:   "key",
				ProjectId:    "project",
			},
			GCEAuthMetadata:   authmetadata.NewHandler(gceAuthMetadataFields),
			IAMAuthMetadata:   authmetadata.NewHandler(iamAuthMetadataFields),
			IAMCustomEndpoint: "https://example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		if _, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]interface{}{
				"credentials": `{
				  "project_id": "2project_id",
				  "private_key_id": "2key_id",
				  "private_key": "2key",
				  "client_email": "2user@test.com",
				  "client_id": "2client_id"
				}`,
				"custom_endpoint": map[string]string{
					"iam": "https://example-iam.com",
				},
			},
		}); err != nil {
			t.Fatal(err)
		}

		config, err := b.config(ctx, storage)
		if err != nil {
			t.Fatal(err)
		}

		creds := config.Credentials
		if creds == nil {
			t.Fatal("expected credentials to exist")
		}

		if v, exp := creds.ClientEmail, "2user@test.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.ClientId, "2client_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.PrivateKeyId, "2key_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.PrivateKey, "2key"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := creds.ProjectId, "2project_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
		if v, exp := config.IAMCustomEndpoint, "https://example-iam.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})
}

func TestConfig_Update(t *testing.T) {
	cases := []struct {
		name      string
		fieldData *framework.FieldData
		original  *gcpConfig
		expected  *gcpConfig
		wantErr   bool
	}{
		{
			name:      "empty",
			fieldData: nil,
			original:  &gcpConfig{},
			expected:  &gcpConfig{},
		},
		{
			name:      "keeps_existing",
			fieldData: nil,
			original: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			expected: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
		},
		{
			name: "overwrites_changes",
			fieldData: &framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": `{
						"client_id": "bar",
						"private_key_id": "aaa"
					}`,
				},
			},
			original: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			expected: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId:     "bar",
					PrivateKeyId: "aaa",
				},
			},
		},
		{
			name: "overwrites_and_new",
			fieldData: &framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": `{
						"client_id": "foo",
						"private_key_id": "aaa"
					}`,
				},
			},
			original: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			expected: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId:     "foo",
					PrivateKeyId: "aaa",
				},
			},
		},
		{
			name: "empty credentials resets to use application default credentials",
			fieldData: &framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "",
				},
			},
			original: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			expected: &gcpConfig{
				Credentials: nil,
			},
		},
		{
			name: "invalid credentials results in error and retains original credentials",
			fieldData: &framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "{}",
				},
			},
			original: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			expected: &gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.original.GCEAuthMetadata = authmetadata.NewHandler(gceAuthMetadataFields)
			tc.original.IAMAuthMetadata = authmetadata.NewHandler(gceAuthMetadataFields)

			if tc.fieldData != nil {
				var b GcpAuthBackend
				tc.fieldData.Schema = pathConfig(&b).Fields
			}

			err := tc.original.Update(tc.fieldData)
			if tc.wantErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			if !reflect.DeepEqual(tc.original.Credentials, tc.expected.Credentials) {
				t.Errorf("expected %+v to be %+v", tc.original.Credentials,
					tc.expected.Credentials)
			}
		})
	}
}

type testSystemView struct {
	logical.StaticSystemView
}

func (d testSystemView) GenerateIdentityToken(_ context.Context, _ *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	return &pluginutil.IdentityTokenResponse{}, nil
}

func (d testSystemView) DeregisterRotationJob(_ context.Context, _ *rotation.RotationJobDeregisterRequest) error {
	return nil
}

// TestConfig_PluginIdentityToken tests that configuring WIF succeeds
// It uses the testSystemView interface to generate the ID token
func TestConfig_PluginIdentityToken(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = &testSystemView{}

	b := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"identity_token_ttl":      int64(10),
		"identity_token_audience": "test-aud",
		"service_account_email":   "test-service_account",
	}

	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config",
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config writing failed: resp:%#v\n err: %v", resp, err)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   config.StorageView,
		Path:      "config",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config reading failed: resp:%#v\n err: %v", resp, err)
	}

	// Grab the subset of fields from the response we care to look at for this case
	got := map[string]interface{}{
		"identity_token_ttl":      resp.Data["identity_token_ttl"],
		"identity_token_audience": resp.Data["identity_token_audience"],
		"service_account_email":   resp.Data["service_account_email"],
	}

	if !reflect.DeepEqual(got, configData) {
		t.Errorf("bad: expected to read config root as %#v, got %#v instead", configData, resp.Data)
	}

	credJson := `{
				  "project_id": "project_id",
				  "private_key_id": "key_id",
				  "private_key": "key",
				  "client_email": "user@test.com",
				  "client_id": "client_id"
				}`
	// mutually exclusive fields must result in an error
	configData = map[string]interface{}{
		"identity_token_audience": "test-aud",
		"credentials":             credJson,
	}

	configReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config",
		Data:      configData,
	}

	resp, err = b.HandleRequest(context.Background(), configReq)
	if err == nil {
		t.Fatalf("expected an error but got nil")
	}
	expectedError := "only one of 'credentials' or 'identity_token_audience' can be set"
	if !strings.Contains(err.Error(), expectedError) {
		t.Fatalf("expected err %s, got %s", expectedError, resp.Error())
	}

	// erase storage so that no service account email is in config
	config.StorageView = &logical.InmemStorage{}
	// missing email with audience must result in an error
	configData = map[string]interface{}{
		"identity_token_audience": "test-aud",
	}

	configReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config",
		Data:      configData,
	}

	resp, err = b.HandleRequest(context.Background(), configReq)
	if err == nil {
		t.Fatalf("expected an error but got nil")
	}
	expectedError = "missing required 'service_account_email' when 'identity_token_audience' is set"
	if !strings.Contains(err.Error(), expectedError) {
		t.Fatalf("expected err %s, got %s", expectedError, resp.Error())
	}
}
