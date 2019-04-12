package gcpauth

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
)

func TestBackend_PathConfigRead(t *testing.T) {
	t.Parallel()

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

		if resp != nil {
			t.Errorf("expected response data to be empty, got %v", resp.Data)
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

		if v, exp := resp.Data["client_email"].(string), "user@test.com"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := resp.Data["client_id"].(string), "user"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := resp.Data["private_key_id"].(string), "key_id"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := resp.Data["project_id"].(string), "project"; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, ok := resp.Data["private_key"]; ok {
			t.Errorf("expected %q to be missing", v)
		}
	})
}

func TestBackend_PathConfigWrite(t *testing.T) {
	t.Parallel()

	t.Run("field_validation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, logical.UpdateOperation, "config")
	})

	t.Run("not_exist", func(t *testing.T) {
		t.Parallel()

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
	})
}

func TestConfig_Update(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		new     *gcpConfig
		d       *framework.FieldData
		r       *gcpConfig
		changed bool
		err     bool
	}{
		{
			"empty",
			&gcpConfig{},
			nil,
			&gcpConfig{},
			false,
			false,
		},
		{
			"keeps_existing",
			&gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			nil,
			&gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			false,
			false,
		},
		{
			"overwrites_changes",
			&gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": `{
						"client_id": "bar",
						"private_key_id": "aaa"
					}`,
				},
			},
			&gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId:     "bar",
					PrivateKeyId: "aaa",
				},
			},
			true,
			false,
		},
		{
			"overwrites_and_new",
			&gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId: "foo",
				},
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": `{
						"client_id": "foo",
						"private_key_id": "aaa"
					}`,
				},
			},
			&gcpConfig{
				Credentials: &gcputil.GcpCredentials{
					ClientId:     "foo",
					PrivateKeyId: "aaa",
				},
			},
			true,
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.d != nil {
				var b GcpAuthBackend
				tc.d.Schema = pathConfig(&b).Fields
			}

			changed, err := tc.new.Update(tc.d)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if changed != tc.changed {
				t.Errorf("expected %t to be %t", changed, tc.changed)
			}

			if v, exp := tc.new.Credentials, tc.r.Credentials; !reflect.DeepEqual(v, exp) {
				t.Errorf("expected %q to be %q", v, exp)
			}
		})
	}
}
