package gcpauth

import (
	"fmt"
	"sync/atomic"
	"time"

	"errors"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathTidyIdentityWhitelist(b *GcpAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy/whitelist/$",
		Fields: map[string]*framework.FieldSchema{
			"tidy_buffer": {
				Type:        framework.TypeDurationSecond,
				Default:     259200,
				Description: `Amount of extra time that must have passed beyond the identity's expiration, before it is removed from the backend storage.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTidyWhitelist,
		},

		HelpSynopsis:    pathTidyIdentityWhitelistSyn,
		HelpDescription: pathTidyIdentityWhitelistDesc,
	}
}

func (b *GcpAuthBackend) pathTidyWhitelist(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, b.tidyWhitelistIdentities(req.Storage, time.Duration(data.Get("tidy_buffer").(int))*time.Second)
}

// tidyWhitelistIdentity is used to delete entries in the whitelist that are expired.
func (b *GcpAuthBackend) tidyWhitelistIdentities(s logical.Storage, buffer time.Duration) error {
	grabbed := atomic.CompareAndSwapUint32(&b.tidyWhitelistGuard, 0, 1)
	if grabbed {
		defer atomic.StoreUint32(&b.tidyWhitelistGuard, 0)
	} else {
		return errors.New("identity whitelist tidy operation already running")
	}

	for _, entityType := range b.whitelistedEntityTypes {
		identities, err := s.List(fmt.Sprintf("whitelist/%s", entityType))
		if err != nil {
			return err
		}

		for _, entityId := range identities {
			entityPath := fmt.Sprintf("%s/%s", entityType, entityId)
			identityEntry, err := s.Get("whitelist/" + entityPath)
			if err != nil {
				return fmt.Errorf("error fetching identity %s: %s", entityPath, err)
			}

			if identityEntry == nil {
				return fmt.Errorf("identity entry for %s is nil", entityPath)
			}

			if identityEntry.Value == nil || len(identityEntry.Value) == 0 {
				return fmt.Errorf("found identity entry for %s but actual identity is empty", entityPath)
			}

			var result whitelistIdentity
			if err := identityEntry.DecodeJSON(&result); err != nil {
				return err
			}

			if time.Now().After(result.ExpiresAt.Add(buffer)) {
				if err := s.Delete("whitelist/" + entityPath); err != nil {
					return fmt.Errorf("error deleting whitelist identity %s from storage: %s", entityPath, err)
				}
			}
		}
	}
	return nil
}

const pathTidyIdentityWhitelistSyn = `
Clean-up whitelist identity entries.
`

const pathTidyIdentityWhitelistDesc = `
When an GCP entity identity is whitelisted, the expiration time of the whitelist
entry is set based on the maximum 'max_ttl' value set on the role or the backend's mount.

When this endpoint is invoked, all the entries that are expired will be deleted.
A 'buffer' duration in seconds can be provided to ensure deletion of
only those entries that expired 'buffer' seconds before.
`
