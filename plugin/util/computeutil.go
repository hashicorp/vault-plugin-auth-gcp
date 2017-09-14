package util

import (
	"fmt"
	"google.golang.org/api/compute/v1"
	"strconv"
	"time"
)

type CustomJWTClaims struct {
	Google *GoogleJWTClaims `json:"google,omitempty"`
}

type GoogleJWTClaims struct {
	Compute *GCEIdentityMetadata `json:"compute_engine,omitempty"`
}

type GCEIdentityMetadata struct {
	// ProjectId is the ID for the project where you created the instance.
	ProjectId string `json:"project_id"  structs:"project_id" mapstructure:"project_id"`

	// ProjectNumber is the unique ID for the project where you created the instance.
	ProjectNumber int64 `json:"project_number" structs:"project_number" mapstructure:"project_number"`

	// Zone is the zone where the instance is located.
	Zone string `json:"zone" structs:"zone" mapstructure:"zone"`

	// InstanceId is the unique ID for the instance to which this token belongs. This ID is unique and never reused.
	InstanceId string `json:"instance_id" structs:"instance_id" mapstructure:"instance_id"`

	// InstanceName is the name of the instance to which this token belongs. This name can be reused by several
	// instances over time, so use the instance_id value to identify a unique instance ID.
	InstanceName string `json:"instance_name" structs:"instance_name" mapstructure:"instance_name"`

	// CreatedAt is a unix timestamp indicating when you created the instance.
	CreatedAt int64 `json:"instance_creation_timestamp" structs:"instance_creation_timestamp" mapstructure:"instance_creation_timestamp"`
}

// GetVerifiedInstance returns the Instance as described by the identity metadata or an error.
// If the instance has an invalid status or its creation timestamp does not match the metadata value,
// this  will return nil and an error.
func (meta *GCEIdentityMetadata) GetVerifiedInstance(gceClient *compute.Service) (*compute.Instance, error) {
	instance, err := gceClient.Instances.Get(meta.ProjectId, meta.Zone, meta.InstanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to find instance associated with token: %v", err)
	}

	if !IsValidInstanceStatus(instance.Status) {
		return nil, fmt.Errorf("authenticating instance %s found but has invalid status '%s'", instance.Name, instance.Status)
	}

	// metadata CreatedAt into time.
	metaTime := time.Unix(meta.CreatedAt, 0)

	// Parse instance creationTimestamp into time.
	actualTime, err := time.Parse(time.RFC3339Nano, instance.CreationTimestamp)
	if err != nil {
		return nil, fmt.Errorf("instance 'creationTimestamp' field could not be parsed into time: %s", instance.CreationTimestamp)
	}

	// Check that timestamps match with 1 sec margin of error
	if metaTime.After(actualTime.Add(time.Second)) || metaTime.Before(actualTime.Add(time.Duration(-1)*time.Second)) {
		return nil, fmt.Errorf("found instance has different creation timestamp from metadata; "+
			"instance: %d, metadata: %s", actualTime.Unix(), meta.CreatedAt)
	}
	return instance, nil
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

func ParseMetadataFromAuth(authMeta map[string]string) (*GCEIdentityMetadata, error) {
	meta := &GCEIdentityMetadata{}
	var err error

	for k, v := range authMeta {
		switch k {
		case "project_id":
			meta.ProjectId = v
		case "zone":
			meta.Zone = v
		case "instance_id":
			meta.InstanceId = v
		case "instance_name":
			meta.InstanceName = v
		case "project_number":
			if meta.ProjectNumber, err = strconv.ParseInt(v, 10, 64); err != nil {
				return nil, err
			}
		case "instance_creation_timestamp":
			if meta.CreatedAt, err = strconv.ParseInt(v, 10, 64); err != nil {
				return nil, err
			}
		default:
			continue
		}
	}

	return meta, nil
}
