package cache

import (
	"fmt"
	"sync"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
)

// cachedResource is used to track resources added by the user in the cache.
// It contains the resource itself and its associated version (currently in two different modes).
type cachedResource struct {
	name string

	// resource must not be modified once the cachedResource is created.
	resource types.Resource
	ttl      *time.Duration

	// cacheVersion is the version of the cache at the time of last update, used in sotw.
	cacheVersion string

	marshalFunc                func() ([]byte, error)
	computeResourceVersionFunc func() (string, error)
}

func newCachedResource(name string, res types.Resource, cacheVersion string) *cachedResource {
	marshalFunc := sync.OnceValues(func() ([]byte, error) {
		return MarshalResource(res)
	})
	return &cachedResource{
		name:         name,
		resource:     res,
		cacheVersion: cacheVersion,
		marshalFunc:  marshalFunc,
		computeResourceVersionFunc: sync.OnceValues(func() (string, error) {
			marshaled, err := marshalFunc()
			if err != nil {
				return "", fmt.Errorf("marshaling resource: %w", err)
			}
			return HashResource(marshaled), nil
		}),
	}
}

func newCachedResourceWithTTL(name string, res types.ResourceWithTTL, cacheVersion string) *cachedResource {
	cachedRes := newCachedResource(name, res.Resource, cacheVersion)
	cachedRes.ttl = res.TTL
	return cachedRes
}

// getMarshaledResource lazily marshals the resource and returns the bytes.
func (c *cachedResource) getMarshaledResource() ([]byte, error) {
	return c.marshalFunc()
}

// getResourceVersion lazily hashes the resource and returns the stable hash used to track version changes.
func (c *cachedResource) getResourceVersion() (string, error) {
	return c.computeResourceVersionFunc()
}

// getVersion returns the requested version.
func (c *cachedResource) getVersion(useResourceVersion bool) (string, error) {
	if !useResourceVersion {
		return c.cacheVersion, nil
	}

	return c.getResourceVersion()
}
