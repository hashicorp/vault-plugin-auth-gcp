package gcpauth

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
)

type aliasData struct {
	role       *gcpRole
	svcAccount *iam.ServiceAccount
	instance   *compute.Instance
}

type iamAliaser func(role *gcpRole, svcAccount *iam.ServiceAccount) (alias string)
type gceAliaser func(role *gcpRole, instance *compute.Instance) (alias string)

const (
	defaultIAMAlias = "unique_id"
	defaultGCEAlias = "instance_id"
)

var (
	allowedIAMAliases = map[string]iamAliaser{
		defaultIAMAlias: getIAMSvcAccountUniqueID,
		"":              getIAMSvcAccountUniqueID, // For backwards compatibility

		"role_id": getIAMRoleID,
	}
	allowedGCEAliases = map[string]gceAliaser{
		defaultGCEAlias: getGCEInstanceID,
		"":              getGCEInstanceID, // For backwards compatibility

		"role_id": getGCERoleID,
	}

	allowedIAMAliasesSlice = iamMapKeyToSlice(allowedIAMAliases)
	allowedGCEAliasesSlice = gceMapKeyToSlice(allowedGCEAliases)
)

func iamMapKeyToSlice(m map[string]iamAliaser) (s []string) {
	for key := range m {
		if key == "" {
			continue
		}
		s = append(s, key)
	}
	sort.Strings(s)
	return s
}

func gceMapKeyToSlice(m map[string]gceAliaser) (s []string) {
	for key := range m {
		if key == "" {
			continue
		}
		s = append(s, key)
	}
	sort.Strings(s)
	return s
}

func getIAMSvcAccountUniqueID(_ *gcpRole, svcAccount *iam.ServiceAccount) (alias string) {
	return svcAccount.UniqueId
}

func getIAMRoleID(role *gcpRole, _ *iam.ServiceAccount) (alias string) {
	return role.RoleID
}

func getGCEInstanceID(_ *gcpRole, instance *compute.Instance) (alias string) {
	return fmt.Sprintf("gce-%s", strconv.FormatUint(instance.Id, 10))
}

func getGCERoleID(role *gcpRole, _ *compute.Instance) (alias string) {
	return role.RoleID
}

func getIAMAlias(role *gcpRole, svcAccount *iam.ServiceAccount) (alias string, err error) {
	aliaser, exists := allowedIAMAliases[role.IAMAliasType]
	if !exists {
		return "", fmt.Errorf("invalid IAM alias type: must be one of: %s", strings.Join(allowedIAMAliasesSlice, ", "))
	}
	return aliaser(role, svcAccount), nil
}

func getGCEAlias(role *gcpRole, instance *compute.Instance) (alias string, err error) {
	aliaser, exists := allowedGCEAliases[role.GCEAliasType]
	if !exists {
		return "", fmt.Errorf("invalid GCE alias type: must be one of: %s", strings.Join(allowedIAMAliasesSlice, ", "))
	}
	return aliaser(role, instance), nil
}
