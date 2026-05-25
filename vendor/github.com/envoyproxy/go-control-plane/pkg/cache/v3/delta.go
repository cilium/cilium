// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package cache

import (
	"context"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
)

// groups together resource-related arguments for the createDeltaResponse function
type resourceContainer struct {
	resourceMap map[string]types.Resource
	versionMap  map[string]string
}

func createDeltaResponse(ctx context.Context, req *DeltaRequest, sub Subscription, resources resourceContainer, cacheVersion string) *RawDeltaResponse {
	// variables to build our response with
	var nextVersionMap map[string]string
	var filtered []*cachedResource
	var toRemove []string

	// If we are handling a wildcard request, we want to respond with all resources
	switch {
	case sub.IsWildcard():
		if len(sub.ReturnedResources()) == 0 {
			filtered = make([]*cachedResource, 0, len(resources.resourceMap))
		}
		nextVersionMap = make(map[string]string, len(resources.resourceMap))
		for name, r := range resources.resourceMap {
			// Since we've already precomputed the version hashes of the new snapshot,
			// we can just set it here to be used for comparison later
			version := resources.versionMap[name]
			nextVersionMap[name] = version
			prevVersion, found := sub.ReturnedResources()[name]
			if !found || (prevVersion != version) {
				filtered = append(filtered, newCachedResource(name, r, version))
			}
		}

		// Compute resources for removal
		// The resource version can be set to "" here to trigger a removal even if never returned before
		for name := range sub.ReturnedResources() {
			if _, ok := resources.resourceMap[name]; !ok {
				toRemove = append(toRemove, name)
			}
		}
	default:
		nextVersionMap = make(map[string]string, len(sub.SubscribedResources()))
		// state.GetResourceVersions() may include resources no longer subscribed
		// In the current code this gets silently cleaned when updating the version map
		for name := range sub.SubscribedResources() {
			prevVersion, found := sub.ReturnedResources()[name]
			if r, ok := resources.resourceMap[name]; ok {
				nextVersion := resources.versionMap[name]
				if prevVersion != nextVersion {
					filtered = append(filtered, newCachedResource(name, r, nextVersion))
				}
				nextVersionMap[name] = nextVersion
			} else if found {
				toRemove = append(toRemove, name)
			}
		}
	}

	return &RawDeltaResponse{
		DeltaRequest:      req,
		resources:         filtered,
		removedResources:  toRemove,
		returnedResources: nextVersionMap,
		SystemVersionInfo: cacheVersion,
		Ctx:               ctx,
	}
}
