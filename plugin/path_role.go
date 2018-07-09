package gcpauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	// Role types
	iamRoleType = "iam"
	gceRoleType = "gce"

	// Errors
	errEmptyRoleName           = "role name is required"
	errEmptyRoleType           = "role type cannot be empty"
	errEmptyProjectId          = "project id cannot be empty"
	errEmptyIamServiceAccounts = "IAM role type must have at least one service account"

	errTemplateEditListWrongType   = "role is type '%s', cannot edit attribute '%s' (expected role type: '%s')"
	errTemplateInvalidRoleTypeArgs = "invalid args found for role of type %s: %s"

	// Other
	serviceAccountsWildcard = "*"

	// Default duration that JWT tokens must expire within to be accepted (currently only IAM)
	defaultIamMaxJwtExpMinutes int = 15

	// Max allowed duration that all JWT tokens must expire within to be accepted
	maxJwtExpMaxMinutes int = 60
)

var baseRoleFieldSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "Name of the role.",
	},
	"type": {
		Type:        framework.TypeString,
		Description: "Type of the role. Currently supported: iam, gce",
	},
	"policies": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Policies to be set on tokens issued using this role.",
	},
	// Token Limits
	"ttl": {
		Type:    framework.TypeDurationSecond,
		Default: 0,
		Description: `
	Duration in seconds after which the issued token should expire. Defaults to 0,
	in which case the value will fallback to the system/mount defaults.`,
	},
	"max_ttl": {
		Type:        framework.TypeDurationSecond,
		Default:     0,
		Description: "The maximum allowed lifetime of tokens issued using this role.",
	},
	"period": {
		Type:    framework.TypeDurationSecond,
		Default: 0,
		Description: `
	If set, indicates that the token generated using this role should never expire. The token should be renewed within the
	duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.`,
	},
	// -- GCP Information
	"project_id": {
		Type:        framework.TypeString,
		Description: `The id of the project that authorized instances must belong to for this role.`,
	},
	"bound_service_accounts": {
		Type: framework.TypeCommaStringSlice,
		Description: `
	Can be set for both 'iam' and 'gce' roles (required for 'iam'). A comma-seperated list of authorized service accounts.
	If the single value "*" is given, this is assumed to be all service accounts under the role's project. If this
	is set on a GCE role, the inferred service account from the instance metadata token will be used.`,
	},
	"service_accounts": {
		Type:        framework.TypeCommaStringSlice,
		Description: `Deprecated, use bound_service_accounts instead.`,
	},
}

var iamOnlyFieldSchema = map[string]*framework.FieldSchema{
	"max_jwt_exp": {
		Type:        framework.TypeDurationSecond,
		Default:     defaultIamMaxJwtExpMinutes * 60,
		Description: `Currently enabled for 'iam' only. Duration in seconds from time of validation that a JWT must expire within.`,
	},
	"allow_gce_inference": {
		Type:        framework.TypeBool,
		Default:     true,
		Description: `'iam' roles only. If false, Vault will not not allow GCE instances to login in against this role`,
	},
}

var gceOnlyFieldSchema = map[string]*framework.FieldSchema{
	"bound_zone": {
		Type: framework.TypeString,
		Description: `
"gce" roles only. If set, determines the zone that a GCE instance must belong to. If a group is provided, it is assumed
to be a zonal group and the group must belong to this zone. Accepts self-link or zone name.`,
	},
	"bound_region": {
		Type: framework.TypeString,
		Description: `
"gce" roles only. If set, determines the region that a GCE instance must belong to. If a group is provided, it is
assumed to be a regional group and the group must belong to this region. If zone is provided, region will be ignored.
Either self-link or region name are accepted.`,
	},
	"bound_instance_group": {
		Type:        framework.TypeString,
		Description: `"gce" roles only. If set, determines the instance group that an authorized instance must belong to.`,
	},
	"bound_labels": {
		Type: framework.TypeCommaStringSlice,
		Description: `
"gce" roles only. A comma-separated list of Google Cloud Platform labels formatted as "$key:$value" strings that are
required for authorized GCE instances.`,
	},
}

// pathsRole creates paths for listing roles and CRUD operations.
func pathsRole(b *GcpAuthBackend) []*framework.Path {
	roleFieldSchema := map[string]*framework.FieldSchema{}
	for k, v := range baseRoleFieldSchema {
		roleFieldSchema[k] = v
	}
	for k, v := range iamOnlyFieldSchema {
		roleFieldSchema[k] = v
	}
	for k, v := range gceOnlyFieldSchema {
		roleFieldSchema[k] = v
	}

	paths := []*framework.Path{
		{
			Pattern:        fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
			Fields:         roleFieldSchema,
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

		// Edit service accounts on an IAM role
		{
			Pattern: fmt.Sprintf("role/%s/service-accounts", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"add": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Service-account emails or IDs to add.",
				},
				"remove": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Service-account emails or IDs to remove.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleEditIamServiceAccounts,
			},
			HelpSynopsis:    "Add or remove service accounts for an existing `iam` role",
			HelpDescription: "Add or remove service accounts from the list bound to an existing `iam` role",
		},

		// Edit labels on an GCE role
		{
			Pattern: fmt.Sprintf("role/%s/labels", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"add": {
					Type:        framework.TypeCommaStringSlice,
					Description: "BoundLabels to add (in $key:$value)",
				},
				"remove": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Label key values to remove",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleEditGceLabels,
			},
			HelpSynopsis: "Add or remove labels for an existing 'gce' role",
			HelpDescription: `Add or remove labels for an existing 'gce' role. 'add' labels should be
			of format '$key:$value' and 'remove' labels should be a list of keys to remove.`,
		},
	}

	return paths
}

func (b *GcpAuthBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *GcpAuthBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	if err := req.Storage.Delete(ctx, fmt.Sprintf("role/%s", name)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *GcpAuthBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	}

	role.Period /= time.Second
	role.TTL /= time.Second
	role.MaxTTL /= time.Second
	role.MaxJwtExp /= time.Second

	return &logical.Response{
		Data: structs.New(role).Map(),
	}, nil
}

func (b *GcpAuthBackend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, data); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	name := strings.ToLower(data.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &gcpRole{}
	}

	warnings, err := role.updateRole(b.System(), req.Operation, data)
	if err != nil {
		resp := logical.ErrorResponse(err.Error())
		for _, w := range warnings {
			resp.AddWarning(w)
		}
		return resp, nil
	}
	return b.storeRole(ctx, req.Storage, name, role, warnings)
}

func (b *GcpAuthBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
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

func (b *GcpAuthBackend) pathRoleEditIamServiceAccounts(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, data); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	var warnings []string

	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	toAdd := data.Get("add").([]string)
	toRemove := data.Get("remove").([]string)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		return logical.ErrorResponse("must provide at least one value to add or remove"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role.RoleType != iamRoleType {
		return logical.ErrorResponse(fmt.Sprintf(errTemplateEditListWrongType, role.RoleType, "service_accounts", iamRoleType)), nil
	}
	role.BoundServiceAccounts = editStringValues(role.BoundServiceAccounts, toAdd, toRemove)

	return b.storeRole(ctx, req.Storage, roleName, role, warnings)
}

func editStringValues(initial []string, toAdd []string, toRemove []string) []string {
	strMap := map[string]struct{}{}
	for _, name := range initial {
		strMap[name] = struct{}{}
	}

	for _, name := range toAdd {
		strMap[name] = struct{}{}
	}

	for _, name := range toRemove {
		delete(strMap, name)
	}

	updated := make([]string, len(strMap))

	i := 0
	for k := range strMap {
		updated[i] = k
		i++
	}

	return updated
}

func (b *GcpAuthBackend) pathRoleEditGceLabels(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, data); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	var warnings []string

	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	toAdd := data.Get("add").([]string)
	toRemove := data.Get("remove").([]string)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		return logical.ErrorResponse("must provide at least one value to add or remove"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role.RoleType != gceRoleType {
		return logical.ErrorResponse(fmt.Sprintf(errTemplateEditListWrongType, role.RoleType, "labels", gceRoleType)), nil
	}

	labelsToAdd, invalidLabels := gcputil.ParseGcpLabels(toAdd)
	if len(invalidLabels) > 0 {
		return logical.ErrorResponse(fmt.Sprintf("given invalid labels to add: %q", invalidLabels)), nil
	}
	for k, v := range labelsToAdd {
		role.BoundLabels[k] = v
	}

	for _, k := range toRemove {
		delete(role.BoundLabels, k)
	}

	return b.storeRole(ctx, req.Storage, roleName, role, warnings)
}

// role reads a gcpRole from storage. This assumes the caller has already obtained the role lock.
func (b *GcpAuthBackend) role(ctx context.Context, s logical.Storage, name string) (*gcpRole, error) {
	name = strings.ToLower(name)

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role gcpRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

}

// storeRole saves the gcpRole to storage.
// The returned response may contain either warnings or an error response,
// but will be nil if error is not nil
func (b *GcpAuthBackend) storeRole(ctx context.Context, s logical.Storage, roleName string, role *gcpRole, warnings []string) (*logical.Response, error) {
	var resp logical.Response
	for _, w := range warnings {
		resp.AddWarning(w)
	}

	validateWarnings, err := role.validate(b.System())
	for _, w := range validateWarnings {
		resp.AddWarning(w)
	}
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", roleName), role)
	if err != nil {
		return nil, err
	}
	if err := s.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &resp, nil
}

type gcpRole struct {
	// Type of this role. See path_role constants for currently supported types.
	RoleType string `json:"role_type,omitempty" structs:"role_type,omitempty"`

	// Project ID in GCP for authorized entities.
	ProjectId string `json:"project_id,omitempty" structs:"project_id,omitempty"`

	// Policies for Vault to assign to authorized entities.
	Policies []string `json:"policies,omitempty" structs:"policies,omitempty"`

	// TTL of Vault auth leases under this role.
	TTL time.Duration `json:"ttl,omitempty" structs:"ttl,omitempty"`

	// Max total TTL including renewals, of Vault auth leases under this role.
	MaxTTL time.Duration `json:"max_ttl,omitempty" structs:"max_ttl,omitempty"`

	// Period, If set, indicates that this token should not expire and
	// should be automatically renewed within this time period
	// with TTL equal to this value.
	Period time.Duration `json:"period,omitempty" structs:"period,omitempty"`

	// Service accounts allowed to login under this role.
	BoundServiceAccounts []string `json:"bound_service_accounts,omitempty" structs:"bound_service_accounts,omitempty"`

	// --| IAM-only attributes |--
	// MaxJwtExp is the duration from time of authentication that a JWT used to authenticate to role must expire within.
	// TODO(emilymye): Allow this to be updated for GCE roles once 'exp' parameter has been allowed for GCE metadata.
	MaxJwtExp time.Duration `json:"max_jwt_exp,omitempty" structs:"max_jwt_exp,omitempty"`

	// AllowGCEInference, if false, does not allow a GCE instance to login under this 'iam' role. If true (default),
	// a service account is inferred from the instance metadata and used as the authenticating instance.
	AllowGCEInference bool `json:"allow_gce_inference,omitempty" structs:"allow_gce_inference,omitempty"`

	// --| GCE-only attributes |--
	// BoundRegion that instances must belong to in order to login under this role.
	BoundRegion string `json:"bound_region" structs:"bound_region" mapstructure:"bound_region"`

	// BoundZone that instances must belong to in order to login under this role.
	BoundZone string `json:"bound_zone" structs:"bound_zone" mapstructure:"bound_zone"`

	// Instance group that instances must belong to in order to login under this role.
	BoundInstanceGroup string `json:"bound_instance_group" structs:"bound_instance_group" mapstructure:"bound_instance_group"`

	// BoundLabels that instances must currently have set in order to login under this role.
	BoundLabels map[string]string `json:"bound_labels" structs:"bound_labels" mapstructure:"bound_labels"`
}

// Update updates the given role with values parsed/validated from given FieldData.
// Exactly one of the response and error will be nil. The response is only used to pass back warnings.
// This method does not validate the role. Validation is done before storage.
func (role *gcpRole) updateRole(sys logical.SystemView, op logical.Operation, data *framework.FieldData) (warnings []string, err error) {
	// Set role type
	roleTypeRaw, ok := data.GetOk("type")
	if ok {
		roleType := roleTypeRaw.(string)
		if role.RoleType != roleType && op == logical.UpdateOperation {
			err = errors.New("role type cannot be changed for an existing role")
			return
		}
		role.RoleType = roleType
	} else if op == logical.CreateOperation {
		err = errors.New(errEmptyRoleType)
		return
	}

	// Update policies
	if policies, ok := data.GetOk("policies"); ok {
		role.Policies = policyutil.ParsePolicies(policies)
	} else if op == logical.CreateOperation {
		// Force default policy
		role.Policies = policyutil.ParsePolicies(nil)
	}

	// Update GCP project id.
	if projectId, ok := data.GetOk("project_id"); ok {
		role.ProjectId = projectId.(string)
	}

	// Update token TTL.
	if ttl, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	}

	// Update token Max TTL.
	if maxTTL, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	}

	// Update token period.
	if period, ok := data.GetOk("period"); ok {
		role.Period = time.Duration(period.(int)) * time.Second
	}

	// Update bound GCP service accounts.
	if sa, ok := data.GetOk("bound_service_accounts"); ok {
		role.BoundServiceAccounts = sa.([]string)
	} else {
		// Check for older version of param name
		if sa, ok := data.GetOk("service_accounts"); ok {
			warnings = append(warnings, `The "service_accounts" field is deprecated. `+
				`Please use "bound_service_accounts" instead. The "service_accounts" `+
				`field will be removed in a later release, so please update accordingly.`)
			role.BoundServiceAccounts = sa.([]string)
		}
	}

	// Update fields specific to this type
	switch role.RoleType {
	case iamRoleType:
		if err = checkInvalidRoleTypeArgs(data, gceOnlyFieldSchema); err != nil {
			return
		}
		if warnings, err = role.updateIamFields(data, op); err != nil {
			return
		}
	case gceRoleType:
		if err = checkInvalidRoleTypeArgs(data, iamOnlyFieldSchema); err != nil {
			return
		}
		if warnings, err = role.updateGceFields(data, op); err != nil {
			return
		}
	}

	return
}

func (role *gcpRole) validate(sys logical.SystemView) (warnings []string, err error) {
	warnings = []string{}

	switch role.RoleType {
	case iamRoleType:
		if warnings, err = role.validateForIAM(); err != nil {
			return warnings, err
		}
	case gceRoleType:
		if warnings, err = role.validateForGCE(); err != nil {
			return warnings, err
		}
	case "":
		return warnings, errors.New(errEmptyRoleType)
	default:
		return warnings, fmt.Errorf("role type '%s' is invalid", role.RoleType)
	}

	if role.ProjectId == "" {
		return warnings, errors.New(errEmptyProjectId)
	}

	defaultLeaseTTL := sys.DefaultLeaseTTL()
	if role.TTL > defaultLeaseTTL {
		warnings = append(warnings, fmt.Sprintf(
			"Given ttl of %d seconds greater than current mount/system default of %d seconds; ttl will be capped at login time",
			role.TTL/time.Second, defaultLeaseTTL/time.Second))
	}

	defaultMaxTTL := sys.MaxLeaseTTL()
	if role.MaxTTL > defaultMaxTTL {
		warnings = append(warnings, fmt.Sprintf(
			"Given max_ttl of %d seconds greater than current mount/system default of %d seconds; max_ttl will be capped at login time",
			role.MaxTTL/time.Second, defaultMaxTTL/time.Second))
	}
	if role.MaxTTL < time.Duration(0) {
		return warnings, errors.New("max_ttl cannot be negative")
	}
	if role.MaxTTL != 0 && role.MaxTTL < role.TTL {
		return warnings, errors.New("ttl should be shorter than max_ttl")
	}

	if role.Period > sys.MaxLeaseTTL() {
		return warnings, fmt.Errorf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", role.Period.String(), sys.MaxLeaseTTL().String())
	}

	return warnings, nil
}

// updateIamFields updates IAM-only fields for a role.
func (role *gcpRole) updateIamFields(data *framework.FieldData, op logical.Operation) (warnings []string, err error) {
	if allowGCEInference, ok := data.GetOk("allow_gce_inference"); ok {
		role.AllowGCEInference = allowGCEInference.(bool)
	} else if op == logical.CreateOperation {
		role.AllowGCEInference = data.Get("allow_gce_inference").(bool)
	}

	if maxJwtExp, ok := data.GetOk("max_jwt_exp"); ok {
		role.MaxJwtExp = time.Duration(maxJwtExp.(int)) * time.Second
	} else if op == logical.CreateOperation {
		role.MaxJwtExp = time.Duration(defaultIamMaxJwtExpMinutes) * time.Minute
	}

	return
}

// updateGceFields updates GCE-only fields for a role.
func (role *gcpRole) updateGceFields(data *framework.FieldData, op logical.Operation) (warnings []string, err error) {
	if regions, ok := data.GetOk("bound_regions"); ok {
		role.BoundRegions = strutil.TrimStrings(regions.([]string))
	}

	if zones, ok := data.GetOk("bound_zones"); ok {
		role.BoundZones = strutil.TrimStrings(zones.([]string))
	}

	if instanceGroups, ok := data.GetOk("bound_instance_groups"); ok {
		role.BoundInstanceGroups = strutil.TrimStrings(instanceGroups.([]string))
	}
	}


	if labelsRaw, ok := data.GetOk("bound_labels"); ok {
		labels, invalidLabels := gcputil.ParseGcpLabels(labelsRaw.([]string))
		if len(invalidLabels) > 0 {
			err = fmt.Errorf("invalid labels given: %q", invalidLabels)
			return
		}
		role.BoundLabels = labels
	}

	return
}

// validateIamFields validates the IAM-only fields for a role.
func (role *gcpRole) validateForIAM() (warnings []string, err error) {
	if len(role.BoundServiceAccounts) == 0 {
		return []string{}, errors.New(errEmptyIamServiceAccounts)
	}

	if len(role.BoundServiceAccounts) > 1 && strutil.StrListContains(role.BoundServiceAccounts, serviceAccountsWildcard) {
		return []string{}, fmt.Errorf("cannot provide IAM service account wildcard '%s' (for all service accounts) with other service accounts", serviceAccountsWildcard)
	}

	maxMaxJwtExp := time.Duration(maxJwtExpMaxMinutes) * time.Minute
	if role.MaxJwtExp > maxMaxJwtExp {
		return warnings, fmt.Errorf("max_jwt_exp cannot be more than %d minutes", maxJwtExpMaxMinutes)
	}

	return []string{}, nil
}

// validateGceFields validates the GCE-only fields for a role.
func (role *gcpRole) validateForGCE() (warnings []string, err error) {
	warnings = []string{}

	hasRegion := len(role.BoundRegion) > 0
	hasZone := len(role.BoundZone) > 0
	hasRegionOrZone := hasRegion || hasZone

	hasInstanceGroup := len(role.BoundInstanceGroup) > 0

	if hasInstanceGroup && !hasRegionOrZone {
		return warnings, errors.New(`region or zone information must be specified if a group is given`)
	}

	if hasRegion && hasZone {
		warnings = append(warnings, "Given both region and zone for role of type 'gce' - region will be ignored.")
	}

	return warnings, nil
}

// checkInvalidRoleTypeArgs checks that the data provided does not contain arguments
// for a different role type. If it does find some, it will return an error with the
// invalid args.
func checkInvalidRoleTypeArgs(data *framework.FieldData, invalidSchema map[string]*framework.FieldSchema) error {
	invalidArgs := []string{}

	for k := range data.Raw {
		if _, ok := baseRoleFieldSchema[k]; ok {
			continue
		}
		if _, ok := invalidSchema[k]; ok {
			invalidArgs = append(invalidArgs, k)
		}
	}

	if len(invalidArgs) > 0 {
		return fmt.Errorf(errTemplateInvalidRoleTypeArgs, data.Get("type"), strings.Join(invalidArgs, ","))
	}
	return nil
}
