package gcpauth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestLogin_IAM(t *testing.T) {
	t.Parallel()

	b, storage, creds := testBackendWithCreds(t)
	ctx := context.Background()

	// Calculate group aliases here once
	crmClient, err := b.CRMClient(storage)
	if err != nil {
		t.Fatal(err)
	}
	groupAliases, err := b.groupAliases(crmClient, ctx, creds.ProjectId)
	if err != nil {
		t.Fatal(err)
	}

	// defaultRole fills in values unless they are already filled in
	defaultRole := func(r *gcpRole) *gcpRole {
		r.RoleID = "testRoleID"

		if r.RoleType == "" {
			r.RoleType = "iam"
		}

		if r.MaxJwtExp == 0 {
			r.MaxJwtExp = 30 * time.Minute
		}

		return r
	}

	cases := []struct {
		name string
		role *gcpRole
		exp  *logical.Response
		err  string
	}{
		{
			"not_bound",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{},
			}),
			nil,
			"not authorized for role",
		},
		{
			"not_bound_project",
			defaultRole(&gcpRole{
				BoundProjects:        []string{"definitely-not-in-this-project"},
				BoundServiceAccounts: []string{creds.ClientEmail},
			}),
			nil,
			"not in bound projects",
		},
		{
			"no_policies",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{creds.ClientEmail},
			}),
			&logical.Response{
				Auth: &logical.Auth{
					LeaseOptions: logical.LeaseOptions{
						Renewable: true,
					},
				},
			},
			"",
		},
		{
			"expire_late",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{creds.ClientEmail},
				MaxJwtExp:            2 * time.Second,
			}),
			nil,
			"expire within 2 seconds",
		},
		{
			"group_aliases",
			defaultRole(&gcpRole{
				AddGroupAliases:      true,
				BoundServiceAccounts: []string{creds.ClientEmail},
			}),
			&logical.Response{
				Auth: &logical.Auth{
					GroupAliases: groupAliases,
				},
			},
			"",
		},
		{
			"wildcard",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{"*"},
			}),
			&logical.Response{
				Auth: &logical.Auth{},
			},
			"",
		},
		{
			"ttl",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{creds.ClientEmail},
				TTL:                  1 * time.Minute,
			}),
			&logical.Response{
				Auth: &logical.Auth{
					LeaseOptions: logical.LeaseOptions{
						TTL: 1 * time.Minute,
					},
				},
			},
			"",
		},
		{
			"max_ttl",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{creds.ClientEmail},
				MaxTTL:               1 * time.Minute,
			}),
			&logical.Response{
				Auth: &logical.Auth{
					LeaseOptions: logical.LeaseOptions{
						MaxTTL: 1 * time.Minute,
					},
				},
			},
			"",
		},
		{
			"period",
			defaultRole(&gcpRole{
				BoundServiceAccounts: []string{creds.ClientEmail},
				Period:               72 * time.Hour,
			}),
			&logical.Response{
				Auth: &logical.Auth{
					Period: 72 * time.Hour,
				},
			},
			"",
		},
	}

	for _, tc := range cases {
		tc := tc // Since the t.Run is parallel, this is needed to prevent scope sharing between loops

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create the role
			role := "test-" + tc.name
			entry, err := logical.StorageEntryJSON("role/"+role, tc.role)
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.Put(ctx, entry); err != nil {
				t.Fatal(err)
			}

			// Build the JWT token
			iamClient, err := b.IAMCredentialsClient(storage)
			if err != nil {
				t.Fatal(err)
			}
			exp := time.Now().Add(10 * time.Minute)
			jwt, err := ServiceAccountLoginJwt(iamClient, exp, "vault/"+role, creds.ClientEmail)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "login",
				Data: map[string]interface{}{
					"role": role,
					"jwt":  jwt.SignedJwt,
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			if resp.IsError() {
				if tc.err == "" {
					t.Fatal(resp.Error())
				}

				// If there was an error, make sure it was the right error
				str := resp.Error().Error()
				if !strings.Contains(str, tc.err) {
					t.Errorf("expected %q to contain %q", str, tc.err)
				}
			}

			if tc.exp != nil && tc.exp.Auth != nil {
				tc.exp.Auth.Alias = &logical.Alias{
					Name: tc.role.RoleID,
				}
				tc.exp.Auth.DisplayName = creds.ClientEmail

				metadata := map[string]string{
					"role":                  role,
					"project_id":            creds.ProjectId,
					"service_account_email": creds.ClientEmail,
					"service_account_id":    creds.ClientId,
				}
				tc.exp.Auth.Metadata = metadata
				tc.exp.Auth.Alias.Metadata = metadata
				tc.exp.Auth.LeaseOptions.Renewable = true
				tc.exp.Auth.Policies = tc.role.Policies

				assert.Equal(t, tc.exp, resp)
			}
		})
	}

	t.Run("jwt_already_expired", func(t *testing.T) {
		t.Parallel()

		// Create the role
		role := "test-jwt_already_expired"
		entry, err := logical.StorageEntryJSON("role/"+role, defaultRole(&gcpRole{
			BoundServiceAccounts: []string{creds.ClientEmail},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		jwt := testCreateExpiredJwtToken(t, "vault/"+role, creds)

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login",
			Data: map[string]interface{}{
				"role": role,
				"jwt":  jwt,
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if !resp.IsError() {
			t.Fatal("expected error")
		}

		if str, exp := resp.Error().Error(), "is expired"; !strings.Contains(str, exp) {
			t.Errorf("expected %q to contain %q", str, exp)
		}
	})
}

func Test_Renew(t *testing.T) {
	b, storage, creds := testBackendWithCreds(t)

	// Build the JWT token
	iamClient, err := b.IAMClient(storage)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(10 * time.Minute)
	jwt, err := ServiceAccountLoginJwt(iamClient, exp, "vault/test", creds.ProjectId, creds.ClientEmail)
	if err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Storage: storage,
		Auth:    &logical.Auth{},
	}

	roleFieldSchema := map[string]*framework.FieldSchema{}
	for k, v := range baseRoleFieldSchema() {
		roleFieldSchema[k] = v
	}
	for k, v := range iamOnlyFieldSchema {
		roleFieldSchema[k] = v
	}

	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":                   "test",
			"type":                   "iam",
			"max_jwt_exp":            30 * time.Minute,
			"bound_service_accounts": creds.ClientEmail,
			// Use the deprecated `policies` field
			"policies": "foo,bar",
		},
		Schema: roleFieldSchema,
	}

	resp, err := b.pathRoleCreateUpdate(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	loginFd := &framework.FieldData{
		Raw: map[string]interface{}{
			"role": "test",
			"jwt":  jwt.SignedJwt,
		},
		Schema: pathLogin(b).Fields,
	}
	resp, err = b.pathLogin(context.Background(), req, loginFd)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}
	req.Auth.InternalData = resp.Auth.InternalData
	req.Auth.Metadata = resp.Auth.Metadata
	req.Auth.LeaseOptions = resp.Auth.LeaseOptions
	req.Auth.Policies = resp.Auth.Policies
	req.Auth.TokenPolicies = req.Auth.Policies
	req.Auth.Period = resp.Auth.Period

	// Normal renewal
	renewFd := &framework.FieldData{}
	resp, err = b.pathLoginRenew(context.Background(), req, renewFd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Change the policies -- this should fail
	fd.Raw["policies"] = "zip,zap"
	resp, err = b.pathRoleCreateUpdate(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(context.Background(), req, renewFd)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("expected error")
	}

	// Put the policies back using the non-deprecated `token_policies` field, this should be okay
	delete(fd.Raw, "policies")
	fd.Raw["token_policies"] = "bar,foo"

	resp, err = b.pathRoleCreateUpdate(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(context.Background(), req, renewFd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}
}

// testCreateExpiredJwtToken creates an expired IAM JWT token
func testCreateExpiredJwtToken(tb testing.TB, roleName string, creds *gcputil.GcpCredentials) string {
	block, _ := pem.Decode([]byte(creds.PrivateKey))
	if block == nil {
		tb.Fatal("expected valid PEM block for test credentials private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		tb.Fatal(err)
	}

	// Create header.
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): creds.PrivateKeyId,
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	builder := jwt.Signed(signer)
	jwt, err := builder.Claims(
		&jwt.Claims{
			Subject:  creds.ClientId,
			Audience: jwt.Audience([]string{fmt.Sprintf(expectedJwtAudTemplate, roleName)}),
			Expiry:   jwt.NewNumericDate(time.Now().Add(-100 * time.Minute)),
		}).CompactSerialize()
	if err != nil {
		tb.Fatal(err)
	}

	return jwt
}
