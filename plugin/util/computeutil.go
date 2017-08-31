package util

import (
	"errors"
	"github.com/SermoDigital/jose/jwt"
	"time"
)

const (
	instanceTemplate                    = "projects/%s/zones/%s/instances/%s"
	instanceGroupTemplate               = "projects/%s/%s/%s/instanceGroups/%s"
	managedInstanceGroupTemplate        = "projects/%s/%s/%s/instanceGroupManagers/%s"
	regionsResourceStr           string = "regions"
	zonesResourceStr             string = "zones"
)

type GCEIdentityMetadata struct {
	// [PROJECT_ID] is the ID for the project where you created the instance.
	ProjectId string `"json": "project_id"  structs:"project_id" mapstructure:"project_id"`

	// [PROJECT_NUMBER] is the unique number for the project where you created the instance.
	ProjectNumber int64 `"json": "project_number" structs:"project_number" mapstructure:"project_number"`

	// [ZONE] is the zone where the instance is located.
	Zone string `"json": "zone" structs:"zone" mapstructure:"zone"`

	// [INSTANCE_ID] is the unique ID for the instance to which this token belongs. This ID is unique and never reused.
	InstanceId string `"json": "instance_id" structs:"instance_id" mapstructure:"instance_id"`

	// [INSTANCE_NAME] is the name of the instance to which this token belongs. This name can be reused by several
	// instances over time, so use the instance_id value to identify a unique instance ID.
	InstanceName string `"json": "instance_name" structs:"instance_name" mapstructure:"instance_name"`

	// [CREATION_TIMESTAMP] is a unix timestamp indicating when you created the instance.
	CreatedAt time.Time `"json": "instance_creation_timestamp" structs:"instance_creation_timestamp" mapstructure:"instance_creation_timestamp"`
}

func ParseGceIdentityMetadata(claims jwt.Claims) (*GCEIdentityMetadata, error) {
	googleMetadataRaw := claims.Get("google")
	if googleMetadataRaw == nil {
		return nil, nil
	}

	googleMetadata, ok := googleMetadataRaw.(map[string]interface{})
	if !ok || googleMetadataRaw == nil {
		return nil, errors.New("'google' JWT claim not a map")
	}

	computeMetadataRaw, ok := googleMetadata["compute_engine"]
	if computeMetadataRaw == nil {
		return nil, errors.New("google[compute_engine] JWT claim not found")
	}
	computeMetadata := computeMetadataRaw.(map[string]interface{})

	createdAt := time.Unix(int64(computeMetadata["instance_creation_timestamp"].(float64)), 0)
	metadata := &GCEIdentityMetadata{
		ProjectId:     computeMetadata["project_id"].(string),
		ProjectNumber: int64(computeMetadata["project_number"].(float64)),
		Zone:          computeMetadata["zone"].(string),
		InstanceId:    computeMetadata["instance_id"].(string),
		InstanceName:  computeMetadata["instance_name"].(string),
		CreatedAt:     createdAt,
	}

	return metadata, nil
}

var validInstanceStates map[string]struct{} = map[string]struct{}{
	"PROVISIONING": struct{}{},
	"RUNNING":      struct{}{},
	"STAGING":      struct{}{},
}

func IsValidInstanceStatus(status string) bool {
	_, ok := validInstanceStates[status]
	return ok
}
