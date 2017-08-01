package gcpauth

import (
	"errors"
	"fmt"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"strings"
	"time"
)

const (
	iamRoleType                = "iam"
	errEmptyRoleName           = "role name is required"
	errEmptyIamServiceAccounts = "IAM role type must have at least one service accounts"
)

// pathsRole creates paths for listing roles and CRUD operations.
func pathsRole(b *GcpAuthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"type": {
					Type:        framework.TypeString,
					Description: "Type of the role. Currently supported: iam",
				},
				"policies": {
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Policies to be set on tokens issued using this role.",
				},
				"project_id": {
					Type:        framework.TypeString,
					Description: `The name of the project for service accounts allowed to authenticate to this role`,
				},
				// Token Limits
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     0,
					Description: `Duration in seconds after which the issued token should expire. Defaults to 0, in which case the value will fallback to the system/mount defaults.`,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     0,
					Description: "The maximum allowed lifetime of tokens issued using this role.",
				},
				"period": {
					Type:        framework.TypeDurationSecond,
					Default:     0,
					Description: `If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.`,
				},
				// IAM Role Domain
				"service_accounts": {
					Type:        framework.TypeString,
					Description: `A comma-seperated list of service accounts to allow to login as this role`,
				},
			},

			ExistenceCheck: b.pathRoleExistenceCheck,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.DeleteOperation: b.pathRoleDelete,
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
			},
			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
		// Paths for listing roles
		{
			Pattern: "role/?",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},

			HelpSynopsis:    pathListRolesHelpSyn,
			HelpDescription: pathListRolesHelpDesc,
		},
		{
			Pattern: "roles/?",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},

			HelpSynopsis:    pathListRolesHelpSyn,
			HelpDescription: pathListRolesHelpDesc,
		},
		b.pathEditServiceAccount(),
	}
}

func (b *GcpAuthBackend) pathRoleExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	b.roleMutex.RLock()
	defer b.roleMutex.RUnlock()

	entry, err := b.role(req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *GcpAuthBackend) pathRoleDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()

	if err := req.Storage.Delete(fmt.Sprintf("role/%s", name)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *GcpAuthBackend) pathRoleRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	b.roleMutex.RLock()
	defer b.roleMutex.RUnlock()

	role, err := b.role(req.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	}

	roleMap := structs.New(role).Map()

	// Display all the durations in seconds
	roleMap["ttl"] = role.TTL / time.Second
	roleMap["max_ttl"] = role.MaxTTL / time.Second
	roleMap["period"] = role.Period / time.Second

	resp := &logical.Response{
		Data: roleMap,
	}
	return resp, nil
}

func (b *GcpAuthBackend) pathRoleCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(data.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()

	role, err := b.role(req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &gcpRole{}
	}

	resp, err := b.updateRole(role, req.Operation, data)

	if err := b.storeRole(req.Storage, name, role); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *GcpAuthBackend) pathRoleList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	b.roleMutex.RLock()
	defer b.roleMutex.RUnlock()

	roles, err := req.Storage.List("role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

const pathRoleHelpSyn = `Create a GCP role with associated policies and required attributes.`
const pathRoleHelpDesc = `
A role is required to login under the GCP auth backend. A role binds Vault policies and has
required attributes that an authenticating entity must fulfill to login against this role.
After authenticating the instance, Vault uses the bound policies to determine which resources
the authorization token for the instance can access.
`

const pathListRolesHelpSyn = `Lists all the roles that are registered with Vault.`
const pathListRolesHelpDesc = `Lists all roles under the GCP backends by name.`

// pathsRoleServiceAccount creates a path for adding or removing service accounts to/from an existing IAM role.
func (b *GcpAuthBackend) pathEditServiceAccount() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("role/%s/service-accounts$", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"add": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A comma-seperated list of service accounts`,
			},
			"remove": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A comma-seperated list of service accounts to remove`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathEditServiceAccountsOperator,
		},
		HelpSynopsis:    pathServiceAccountHelpSyn,
		HelpDescription: pathServiceAccountHelpDesc,
	}
}

// pathsRoleServiceAccount returns the OperationFunc for updating a service accounts given an update function.
func (b *GcpAuthBackend) pathEditServiceAccountsOperator(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	toAdd := data.Get("add").([]string)
	toRemove := data.Get("remove").([]string)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		return logical.ErrorResponse("must provide at least one service account to add or remove"), nil
	}

	addServiceAccounts(role, toAdd)
	removeServiceAccounts(role, toRemove)

	if len(role.ServiceAccounts) == 0 {
		return logical.ErrorResponse(errEmptyIamServiceAccounts), nil
	}

	if err := b.storeRole(req.Storage, name, role); err != nil {
		return nil, err
	}
	return nil, nil
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

type gcpRole struct {
	RoleType  string   `json:"role_type" structs:"role_type" mapstructure:"role_type"`
	ProjectId string   `json:"project_id" structs:"project_id" mapstructure:"project_id"`
	Policies  []string `json:"policies" structs:"policies" mapstructure:"policies"`

	TTL    time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Period time.Duration `json:"period" structs:"period" mapstructure:"period"`

	// IAM-specific attributes
	ServiceAccounts []string `json:"service_accounts" structs:"service_accounts" mapstructure:"service_accounts"`
}

// Update updates the given role with values parsed/validated from given FieldData.
// The response is only used to pass back warnings. If there is an error in updating, it is returned in the error field.
func (b *GcpAuthBackend) updateRole(role *gcpRole, op logical.Operation, data *framework.FieldData) (*logical.Response, error) {
	warnResp := &logical.Response{}

	if role == nil {
		return nil, errors.New("role expected to be created before update")
	}

	// Update policies.
	role.Policies = policyutil.ParsePolicies(data.Get("policies").(string))
	if len(role.Policies) == 0 {
		return nil, errors.New("role must have at least one bound policy")
	}

	// Update GCP project name.
	projectNameRaw, ok := data.GetOk("project_id")
	if ok {
		role.ProjectId = projectNameRaw.(string)
	}
	if role.ProjectId == "" {
		return nil, errors.New("role cannot have empty project name")
	}

	// Update token TTL.
	ttlRaw, ok := data.GetOk("ttl")
	if ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
		defaultLeaseTTL := b.System().DefaultLeaseTTL()
		if role.TTL > defaultLeaseTTL {
			warnResp.AddWarning(fmt.Sprintf(
				"Given ttl of %d seconds greater than current mount/system default of %d seconds; ttl will be capped at login time",
				role.TTL/time.Second, defaultLeaseTTL/time.Second))
		}
	} else if op == logical.CreateOperation {
		role.TTL = time.Duration(data.Get("ttl").(int)) * time.Second
	}

	// Update token Max TTL.
	maxTTLInt, ok := data.GetOk("max_ttl")
	if ok {
		role.MaxTTL = time.Duration(maxTTLInt.(int)) * time.Second
		systemMaxTTL := b.System().MaxLeaseTTL()
		if role.MaxTTL > systemMaxTTL {
			warnResp.AddWarning(fmt.Sprintf(
				"Given max_ttl of %d seconds greater than current mount/system default of %d seconds; max_ttl will be capped at login time",
				role.MaxTTL/time.Second, systemMaxTTL/time.Second))
		}
	} else if op == logical.CreateOperation {
		role.MaxTTL = time.Duration(data.Get("max_ttl").(int)) * time.Second
	}
	if role.MaxTTL < time.Duration(0) {
		return nil, errors.New("max_ttl cannot be negative")
	}
	if role.MaxTTL != 0 && role.MaxTTL < role.TTL {
		return nil, errors.New("ttl should be shorter than max_ttl")
	}

	// Update token period.
	periodRaw, ok := data.GetOk("period")
	if ok {
		role.Period = time.Second * time.Duration(periodRaw.(int))
	} else if op == logical.CreateOperation {
		role.Period = time.Second * time.Duration(data.Get("period").(int))
	}
	if role.Period > b.System().MaxLeaseTTL() {
		fmt.Errorf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", role.Period.String(), b.System().MaxLeaseTTL().String())
	}

	// Set role type and update fields specific to this type
	roleTypeRaw, ok := data.GetOk("type")
	if ok {
		if op == logical.UpdateOperation {
			return nil, errors.New("role type cannot be changed for an existing role")
		}
		role.RoleType = roleTypeRaw.(string)
	} else if op == logical.CreateOperation {
		return nil, errors.New("role type must be provided for a new role")
	}

	switch role.RoleType {
	case iamRoleType:
		if err := role.updateIamFields(data); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("role type '%s' is not supported", role.RoleType)
	}

	if len(warnResp.Warnings) == 0 {
		warnResp = nil
	}
	return warnResp, nil
}

// updateIamFields updates IAM-role-only fields
func (role *gcpRole) updateIamFields(data *framework.FieldData) error {
	serviceAccountsRaw, ok := data.GetOk("service_accounts")
	if ok {
		role.ServiceAccounts = strings.Split(serviceAccountsRaw.(string), ",")
	}
	if len(role.ServiceAccounts) == 0 {
		return errors.New(errEmptyIamServiceAccounts)
	}

	return nil
}

// role reads a gcpRole from storage. This assumes the caller has already obtained the role lock.
func (b *GcpAuthBackend) role(s logical.Storage, name string) (*gcpRole, error) {
	entry, err := s.Get(fmt.Sprintf("role/%s", strings.ToLower(name)))

	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := &gcpRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

// storeRole saves the gcpRole to storage.
func (b *GcpAuthBackend) storeRole(s logical.Storage, roleName string, role *gcpRole) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", roleName), role)
	if err != nil {
		return err
	}

	return s.Put(entry)
}
