package gcpauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestRoleResolution(t *testing.T) {
	t.Parallel()

	backend, storage := testBackend(t)
	ctx := context.Background()

	role := &gcpRole{
		RoleID:    "testRoleID",
		RoleType:  "iam",
		MaxJwtExp: 30 * time.Minute,
	}

	roleName := "role-name"
	entry, err := logical.StorageEntryJSON("role/"+roleName, role)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"role": roleName,
		},
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := backend.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["role"] != roleName {
		t.Fatalf("Role was not as expected. Expected %s, received %s", roleName, resp.Data["role"])
	}
}

func TestRoleResolution_RoleDoesNotExist(t *testing.T) {
	t.Parallel()

	backend, storage := testBackend(t)

	roleName := "role-name"

	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data: map[string]interface{}{
			"role": roleName,
		},
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := backend.HandleRequest(context.Background(), loginReq)
	if resp == nil && !resp.IsError() {
		t.Fatalf("Response was not an error: err:%v resp:%#v", err, resp)
	}

	errString, ok := resp.Data["error"].(string)
	if !ok {
		t.Fatal("Error not part of response.")
	}

	if !strings.Contains(errString, "role \"role-name\" not found") {
		t.Fatalf("Error was not due to invalid role name. Error: %s", errString)
	}
}

func TestLogin_IAM(t *testing.T) {
	t.Parallel()

	b, storage, creds := testBackendWithCreds(t)
	ctx := context.Background()

	// Calculate group aliases here once
	crmClient, err := b.CRMClient(ctx, storage)
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

			if _, err := b.HandleRequest(ctx, &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "config",
				Data: map[string]interface{}{
					"custom_endpoint": map[string]string{
						"iam": "https://iam.googleapis.com/",
					},
				},
			}); err != nil {
				t.Fatal(err)
			}

			// Create the role
			role := "test-" + tc.name
			entry, err := logical.StorageEntryJSON("role/"+role, tc.role)
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.Put(ctx, entry); err != nil {
				t.Fatal(err)
			}

			// Get a signed JWT using the service account
			exp := time.Now().Add(10 * time.Minute)
			iamClient := testIAMCredentialsClient(t, creds)
			jwt := testServiceAccountSignJwt(t, iamClient, exp, "vault/"+role, creds.ClientEmail)

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

func TestLogin_IAM_Custom_Endpoint(t *testing.T) {
	b, storage, creds := testBackendWithCreds(t)
	ctx := context.Background()

	cases := []struct {
		name           string
		customEndpoint map[string]string
		wantErr        bool
	}{
		{
			name: "IAM login with invalid api custom endpoints results in error",
			customEndpoint: map[string]string{
				"api":     "https://www.example.com",
				"iam":     "https://iam.googleapis.com",
				"crm":     "https://cloudresourcemanager.googleapis.com",
				"compute": "https://compute.googleapis.com",
			},
			wantErr: true,
		},
		{
			name: "IAM login with invalid iam custom endpoints results in error",
			customEndpoint: map[string]string{
				"api":     "https://www.googleapis.com",
				"iam":     "https://iam.example.com",
				"crm":     "https://cloudresourcemanager.googleapis.com",
				"compute": "https://compute.googleapis.com",
			},
			wantErr: true,
		},
		{
			name: "IAM login with invalid crm custom endpoints results in error",
			customEndpoint: map[string]string{
				"api":     "https://www.googleapis.com",
				"iam":     "https://iam.googleapis.com",
				"crm":     "https://cloudresourcemanager.example.com",
				"compute": "https://compute.googleapis.com",
			},
			wantErr: true,
		},
		{
			name: "IAM login with invalid compute custom endpoints results in success",
			customEndpoint: map[string]string{
				"api": "https://www.googleapis.com",
				"iam": "https://iam.googleapis.com",
				"crm": "https://cloudresourcemanager.googleapis.com",

				// compute only used for GCE-based login
				"compute": "https://compute.example.com",
			},
		},
		{
			name: "IAM login with default custom endpoints results in success",
			customEndpoint: map[string]string{
				"api":     "https://www.googleapis.com",
				"iam":     "https://iam.googleapis.com",
				"crm":     "https://cloudresourcemanager.googleapis.com",
				"compute": "https://compute.googleapis.com",
			},
		},
		{
			name:           "IAM login with empty custom endpoints results in success",
			customEndpoint: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "config",
				Data: map[string]interface{}{
					"custom_endpoint": tc.customEndpoint,
					"iam_alias":       "unique_id",
				},
			}
			resp, err := b.HandleRequest(ctx, req)
			assert.NoError(t, err)
			assert.False(t, resp.IsError())

			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "role/test",
				Storage:   storage,
				Data: map[string]interface{}{
					"type":                   "iam",
					"add_group_aliases":      true,
					"bound_service_accounts": creds.ClientEmail,
				},
			}
			resp, err = b.HandleRequest(ctx, req)
			assert.NoError(t, err)
			assert.False(t, resp.IsError())

			// Get a signed JWT using the service account
			exp := time.Now().Add(10 * time.Minute)
			iamClient := testIAMCredentialsClient(t, creds)
			jwt := testServiceAccountSignJwt(t, iamClient, exp, "vault/test", creds.ClientEmail)

			// Authenticate by providing the signed JWT to the login API
			req = &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "login",
				Data: map[string]interface{}{
					"role": "test",
					"jwt":  jwt.SignedJwt,
				},
			}
			resp, err = b.HandleRequest(ctx, req)
			if tc.wantErr {
				assert.True(t, resp.IsError() || err != nil, "expected error from login API")
				return
			}

			// Assert the auth data in the response is as expected
			assert.NotNil(t, resp.Auth)
			assert.Equal(t, creds.ClientId, resp.Auth.Alias.Name)
			assert.Equal(t, creds.ClientEmail, resp.Auth.DisplayName)
			expectedMetadata := map[string]string{
				"role":                  "test",
				"project_id":            creds.ProjectId,
				"service_account_email": creds.ClientEmail,
				"service_account_id":    creds.ClientId,
			}
			assert.Equal(t, expectedMetadata, resp.Auth.Metadata)
			assert.Equal(t, expectedMetadata, resp.Auth.Alias.Metadata)
		})
	}
}

func Test_Renew(t *testing.T) {
	b, storage, creds := testBackendWithCreds(t)

	// Get a signed JWT using the service account
	exp := time.Now().Add(10 * time.Minute)
	iamClient := testIAMCredentialsClient(t, creds)
	jwt := testServiceAccountSignJwt(t, iamClient, exp, "vault/test", creds.ClientEmail)

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

// testIAMCredentialsClient returns a new IAM Service Account Credentials client.
// This client can be used to sign JWTs using the IAM Service Credentials endpoint.
func testIAMCredentialsClient(t *testing.T, creds *gcputil.GcpCredentials) *iamcredentials.Service {
	t.Helper()

	client, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
	iamClient, err := iamcredentials.NewService(context.Background(), option.WithHTTPClient(client))
	assert.NoError(t, err)
	return iamClient
}

func testServiceAccountSignJwt(t *testing.T, iamClient *iamcredentials.Service, exp time.Time, aud, serviceAccount string) *iamcredentials.SignJwtResponse {
	t.Helper()

	// Marshall claims to JSON
	payload, err := json.Marshal(map[string]interface{}{
		"sub": serviceAccount,
		"aud": aud,
		"exp": exp.Unix(),
	})
	assert.NoError(t, err)

	// Send the request to have GCP sign the JWT
	jwtReq := &iamcredentials.SignJwtRequest{
		Payload: string(payload),
	}
	accountResource := fmt.Sprintf(gcputil.ServiceAccountCredentialsTemplate, serviceAccount)
	resp, err := iamClient.Projects.ServiceAccounts.SignJwt(accountResource, jwtReq).Do()
	assert.NoError(t, err)
	return resp
}

// testCreateExpiredJwtToken creates an expired IAM JWT token
func testCreateExpiredJwtToken(tb testing.TB, roleName string, creds *gcputil.GcpCredentials) string {
	tb.Helper()

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
			"kid": creds.PrivateKeyId,
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	builder := jwt.Signed(signer)
	jwt, err := builder.Claims(
		&jwt.Claims{
			Subject:  creds.ClientId,
			Audience: []string{fmt.Sprintf(expectedJwtAudTemplate, roleName)},
			Expiry:   jwt.NewNumericDate(time.Now().Add(-100 * time.Minute)),
		}).CompactSerialize()
	if err != nil {
		tb.Fatal(err)
	}

	return jwt
}
