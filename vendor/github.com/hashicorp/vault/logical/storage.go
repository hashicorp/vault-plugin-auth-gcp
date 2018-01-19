package logical

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/jsonutil"
)

// ErrReadOnly is returned when a backend does not support
// writing. This can be caused by a read-only replica or secondary
// cluster operation.
var ErrReadOnly = errors.New("Cannot write to readonly storage")

// Storage is the way that logical backends are able read/write data.
type Storage interface {
	List(context.Context, string) ([]string, error)
	Get(context.Context, string) (*StorageEntry, error)
	Put(context.Context, *StorageEntry) error
	Delete(context.Context, string) error
}

// StorageEntry is the entry for an item in a Storage implementation.
type StorageEntry struct {
	Key      string
	Value    []byte
	SealWrap bool
}

// DecodeJSON decodes the 'Value' present in StorageEntry.
func (e *StorageEntry) DecodeJSON(out interface{}) error {
	return jsonutil.DecodeJSON(e.Value, out)
}

// StorageEntryJSON creates a StorageEntry with a JSON-encoded value.
func StorageEntryJSON(k string, v interface{}) (*StorageEntry, error) {
	encodedBytes, err := jsonutil.EncodeJSON(v)
	if err != nil {
		return nil, fmt.Errorf("failed to encode storage entry: %v", err)
	}

	return &StorageEntry{
		Key:   k,
		Value: encodedBytes,
	}, nil
}

type ClearableView interface {
	List(context.Context, string) ([]string, error)
	Delete(context.Context, string) error
}

// ScanView is used to scan all the keys in a view iteratively
func ScanView(ctx context.Context, view ClearableView, cb func(path string)) error {
	frontier := []string{""}
	for len(frontier) > 0 {
		n := len(frontier)
		current := frontier[n-1]
		frontier = frontier[:n-1]

		// List the contents
		contents, err := view.List(ctx, current)
		if err != nil {
			return fmt.Errorf("list failed at path '%s': %v", current, err)
		}

		// Handle the contents in the directory
		for _, c := range contents {
			fullPath := current + c
			if strings.HasSuffix(c, "/") {
				frontier = append(frontier, fullPath)
			} else {
				cb(fullPath)
			}
		}
	}
	return nil
}

// CollectKeys is used to collect all the keys in a view
func CollectKeys(ctx context.Context, view ClearableView) ([]string, error) {
	// Accumulate the keys
	var existing []string
	cb := func(path string) {
		existing = append(existing, path)
	}

	// Scan for all the keys
	if err := ScanView(ctx, view, cb); err != nil {
		return nil, err
	}
	return existing, nil
}

// ClearView is used to delete all the keys in a view
func ClearView(ctx context.Context, view ClearableView) error {
	if view == nil {
		return nil
	}

	// Collect all the keys
	keys, err := CollectKeys(ctx, view)
	if err != nil {
		return err
	}

	// Delete all the keys
	for _, key := range keys {
		if err := view.Delete(ctx, key); err != nil {
			return err
		}
	}
	return nil
}
