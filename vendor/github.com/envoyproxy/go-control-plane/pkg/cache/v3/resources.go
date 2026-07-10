package cache

import "github.com/envoyproxy/go-control-plane/pkg/cache/types"

// Resources is a versioned group of resources.
type Resources struct {
	// Version information.
	Version string

	// Items in the group indexed by name.
	Items map[string]types.ResourceWithTTL
}

// IndexResourcesByName creates a map from the resource name to the resource.
func IndexResourcesByName(items []types.ResourceWithTTL) map[string]types.ResourceWithTTL {
	indexed := make(map[string]types.ResourceWithTTL, len(items))
	for _, item := range items {
		indexed[GetResourceName(item.Resource)] = item
	}
	return indexed
}

// IndexRawResourcesByName creates a map from the resource name to the resource.
func IndexRawResourcesByName(items []types.Resource) map[string]types.Resource {
	indexed := make(map[string]types.Resource, len(items))
	for _, item := range items {
		indexed[GetResourceName(item)] = item
	}
	return indexed
}

// NewResources creates a new resource group.
func NewResources(version string, items []types.Resource) Resources {
	itemsWithTTL := make([]types.ResourceWithTTL, 0, len(items))
	for _, item := range items {
		itemsWithTTL = append(itemsWithTTL, types.ResourceWithTTL{Resource: item})
	}
	return NewResourcesWithTTL(version, itemsWithTTL)
}

// NewResourcesWithTTL creates a new resource group.
func NewResourcesWithTTL(version string, items []types.ResourceWithTTL) Resources {
	return Resources{
		Version: version,
		Items:   IndexResourcesByName(items),
	}
}
