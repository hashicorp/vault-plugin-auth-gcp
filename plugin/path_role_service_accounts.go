package gcpauth

import (
	"fmt"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// pathsRoleServiceAccount generates the path for updating a service accounts through some update function.
func (b *GcpAuthBackend) pathEditServiceAccount(pathSuffix string, updateFunc updateServiceAccountsFunc) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("role/%s/%s$", framework.GenericNameRegex("name"), pathSuffix),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"service_accounts": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A comma-seperated list of service accounts`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathEditServiceAccountsOperator(updateFunc),
		},
		HelpSynopsis:    pathServiceAccountHelpSyn,
		HelpDescription: pathServiceAccountHelpDesc,
	}
}

// pathsRoleServiceAccount returns the OperationFunc for updating a service accounts given an update function.
func (b *GcpAuthBackend) pathEditServiceAccountsOperator(updateFunc updateServiceAccountsFunc) framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)
		if name == "" {
			return logical.ErrorResponse(errEmptyRoleName), nil
		}

		role, err := b.role(req.Storage, name)
		if err != nil {
			return nil, err
		}

		if role.RoleType != iamRoleType {
			return logical.ErrorResponse(fmt.Sprintf("cannot update %s-specific attribute service accounts for role type %s", iamRoleType, role.RoleType)), nil
		}

		accounts := data.Get("service_accounts").([]string)
		if len(accounts) == 0 {
			return logical.ErrorResponse("must provide at least one value for service_accounts parameter"), nil
		}

		updateFunc(role, data.Get("service_accounts").([]string))
		if len(role.ServiceAccounts) == 0 {
			return logical.ErrorResponse(errEmptyIamServiceAccounts), nil
		}

		if err := b.storeRole(req.Storage, name, role); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

// updateServiceAccountsFunc is an update function for the service accounts of a role.
type updateServiceAccountsFunc func(*gcpRole, []string)

func addServiceAccounts(role *gcpRole, accounts []string) {
	serviceAccounts := append(role.ServiceAccounts, accounts...)
	role.ServiceAccounts = strutil.RemoveDuplicates(serviceAccounts, false)
}

func removeServiceAccounts(role *gcpRole, accounts []string) {
	accountMap := map[string]bool{}
	for _, name := range role.ServiceAccounts {
		accountMap[name] = true
	}

	for _, name := range accounts {
		delete(accountMap, name)
	}

	updatedAccounts := []string{}
	for name := range accountMap {
		updatedAccounts = append(updatedAccounts, name)
	}

	role.ServiceAccounts = updatedAccounts
}

const pathServiceAccountHelpSyn = `Edit service accounts associated with an existing GCP IAM role`
const pathServiceAccountHelpDesc = `
This special path allows a user to add, remove, or set the service accounts allowed to login for an existing
GCP IAM role.`
