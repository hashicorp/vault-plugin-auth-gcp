package gcpauth

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
)

// gcpConfig contains all config required for the GCP backend.
type gcpConfig struct {
	Credentials  *gcputil.GcpCredentials `json:"credentials"`
	IAMAliasType string                  `json:"iam_alias"`
	GCEAliasType string                  `json:"gce_alias"`
}

func (c *gcpConfig) getIAMAlias(role *gcpRole, svcAccount *iam.ServiceAccount) (alias string, err error) {
	aliasType := c.IAMAliasType
	if aliasType == "" {
		aliasType = defaultIAMAlias
	}

	aliaser, exists := allowedIAMAliases[aliasType]
	if !exists {
		return "", fmt.Errorf("invalid IAM alias type: must be one of: %s", strings.Join(allowedIAMAliasesSlice, ", "))
	}
	return aliaser(role, svcAccount), nil
}

func (c *gcpConfig) getGCEAlias(role *gcpRole, instance *compute.Instance) (alias string, err error) {
	aliasType := c.GCEAliasType
	if aliasType == "" {
		aliasType = defaultGCEAlias
	}

	aliaser, exists := allowedGCEAliases[aliasType]
	if !exists {
		return "", fmt.Errorf("invalid GCE alias type: must be one of: %s", strings.Join(allowedIAMAliasesSlice, ", "))
	}
	return aliaser(role, instance), nil
}
