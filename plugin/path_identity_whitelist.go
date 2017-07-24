package gcpauth

import (
	"fmt"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"time"
)

const (
	iamEntityType = "service-accounts"
)

func pathsIdentityWhitelist(b *GcpAuthBackend) []*framework.Path {
	paths := []*framework.Path{}
	for _, entityType := range b.whitelistedEntityTypes {
		paths = append(paths, b.pathsIdentityWhitelist(entityType)...)
	}

	return paths
}

func (b *GcpAuthBackend) pathsIdentityWhitelist(entityType string) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("whitelist/%s/%s", entityType, framework.GenericNameRegex("entity_id")),
			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: `ID of entity associated with this login identity.`,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathIdentityWhitelistRead(entityType),
				logical.DeleteOperation: b.pathIdentityWhitelistDelete(entityType),
			},

			HelpSynopsis:    pathIdentityWhitelistSyn,
			HelpDescription: pathIdentityWhitelistDesc,
		},
		{
			Pattern: fmt.Sprintf("whitelist/%s/?", entityType),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathListWhitelistIdentities(entityType),
			},

			HelpSynopsis:    pathListIdentityWhitelistHelpSyn,
			HelpDescription: pathListIdentityWhitelistHelpDesc,
		},
	}
}

func (b *GcpAuthBackend) pathIdentityWhitelistRead(entityType string) framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		entityId, ok := data.GetOk("entity_id")
		if !ok || entityId.(string) == "" {
			return logical.ErrorResponse("entity id is required"), nil
		}

		identity, err := b.whitelistedIdentity(req.Storage, entityType, entityId.(string))
		if err != nil {
			return nil, err
		}

		return &logical.Response{
			Data: structs.New(identity).Map(),
		}, nil
	}
}

func (b *GcpAuthBackend) pathIdentityWhitelistDelete(entityType string) framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		entityId, ok := data.GetOk("entity_id")
		if !ok || entityId.(string) == "" {
			return logical.ErrorResponse("entity id is required"), nil
		}

		return nil, req.Storage.Delete(fmt.Sprintf("whitelist/%s/%s", entityType, entityId.(string)))
	}
}

func (b *GcpAuthBackend) pathListWhitelistIdentities(entityType string) framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		values, err := req.Storage.List(fmt.Sprintf("whitelist/%s/", entityType))
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(values), nil
	}
}

const pathIdentityWhitelistSyn = `Read or delete entries in the identity whitelist.`
const pathIdentityWhitelistDesc = `
Each login creates or updates an identity entry in the whitelist. Entries can be viewed
or deleted using this endpoint.

An identity entry has an associated entity type and id. For example, for IAM,
the entity type is "service-accounts", the entity id is the unique ID of
the service account, and the entry is saved at path "whitelist/service-accounts/$id".

By default, a cron task will periodically delete expired
entries (see 'config' endpoint to disable this task or edit attributes).
This tidy action can also be triggered via the  API 'tidy/whitelist' endpoint.
`

const pathListIdentityWhitelistHelpSyn = `Lists all cached login identities.`
const pathListIdentityWhitelistHelpDesc = `
This endpoint lists all the identity entries present, both expired and
un-expired. Use 'tidy/identities' endpoint to clean-up identities.
`

type whitelistIdentity struct {
	Role                    string `json:"role" structs:"role" mapstructure:"role"`
	EntityType              string `json:"entity_type" structs:"entity_type" mapstructure:"entity_type"`
	EntityId                string `json:"entity_id" structs:"entity_id" mapstructure:"entity_id"`
	ClientNonce             string `json:"client_nonce" structs:"client_nonce" mapstructure:"client_nonce"`
	DisableReauthentication bool   `json:"disable_reauthentication" structs:"disable_reauthentication" mapstructure:"disable_reauthentication"`

	// Vault-specific timestamps.
	CreatedAt time.Time `json:"created_at" structs:"created_at" mapstructure:"created_at"`
	UpdatedAt time.Time `json:"updated_at" structs:"updated_at" mapstructure:"updated_at"`
	ExpiresAt time.Time `json:"expires_at" structs:"expires_at" mapstructure:"expires_at"`

	// JWT timestamps.
	// Corresponding to JWT fields 'iat'. Only set if expected in token.
	TokenIss time.Time `json:"token_iss" structs:"token_iss" mapstructure:"token_iss"`

	// Corresponding to JWT fields 'exp'.
	TokenExp time.Time `json:"token_exp" structs:"token_exp" mapstructure:"token_exp"`
}

func (b *GcpAuthBackend) upsertIdentity(s logical.Storage, identity *whitelistIdentity) error {

	storagePath := fmt.Sprintf("whitelist/%s/%s", identity.EntityType, identity.EntityId)
	entry, err := logical.StorageEntryJSON(storagePath, identity)
	if err != nil {
		return err
	}

	return s.Put(entry)
}

func (b *GcpAuthBackend) whitelistedIdentity(s logical.Storage, entityType, entityId string) (*whitelistIdentity, error) {
	entry, err := s.Get(fmt.Sprintf("whitelist/%s/%s", entityType, entityId))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	identity := &whitelistIdentity{}
	if err = entry.DecodeJSON(identity); err != nil {
		return nil, err
	}

	return identity, nil
}
