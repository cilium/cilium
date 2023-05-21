/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiutil

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/restmapper"
)

// lazyRESTMapper is a RESTMapper that will lazily query the provided
// client for discovery information to do REST mappings.
type lazyRESTMapper struct {
	mapper      meta.RESTMapper
	client      *discovery.DiscoveryClient
	knownGroups map[string]*restmapper.APIGroupResources
	apiGroups   []metav1.APIGroup

	// mutex to provide thread-safe mapper reloading.
	mu sync.Mutex
}

// newLazyRESTMapperWithClient initializes a LazyRESTMapper with a custom discovery client.
func newLazyRESTMapperWithClient(discoveryClient *discovery.DiscoveryClient) (meta.RESTMapper, error) {
	return &lazyRESTMapper{
		mapper:      restmapper.NewDiscoveryRESTMapper([]*restmapper.APIGroupResources{}),
		client:      discoveryClient,
		knownGroups: map[string]*restmapper.APIGroupResources{},
		apiGroups:   []metav1.APIGroup{},
	}, nil
}

// KindFor implements Mapper.KindFor.
func (m *lazyRESTMapper) KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	res, err := m.mapper.KindFor(resource)
	if meta.IsNoMatchError(err) {
		if err = m.addKnownGroupAndReload(resource.Group, resource.Version); err != nil {
			return res, err
		}

		res, err = m.mapper.KindFor(resource)
	}

	return res, err
}

// KindsFor implements Mapper.KindsFor.
func (m *lazyRESTMapper) KindsFor(resource schema.GroupVersionResource) ([]schema.GroupVersionKind, error) {
	res, err := m.mapper.KindsFor(resource)
	if meta.IsNoMatchError(err) {
		if err = m.addKnownGroupAndReload(resource.Group, resource.Version); err != nil {
			return res, err
		}

		res, err = m.mapper.KindsFor(resource)
	}

	return res, err
}

// ResourceFor implements Mapper.ResourceFor.
func (m *lazyRESTMapper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	res, err := m.mapper.ResourceFor(input)
	if meta.IsNoMatchError(err) {
		if err = m.addKnownGroupAndReload(input.Group, input.Version); err != nil {
			return res, err
		}

		res, err = m.mapper.ResourceFor(input)
	}

	return res, err
}

// ResourcesFor implements Mapper.ResourcesFor.
func (m *lazyRESTMapper) ResourcesFor(input schema.GroupVersionResource) ([]schema.GroupVersionResource, error) {
	res, err := m.mapper.ResourcesFor(input)
	if meta.IsNoMatchError(err) {
		if err = m.addKnownGroupAndReload(input.Group, input.Version); err != nil {
			return res, err
		}

		res, err = m.mapper.ResourcesFor(input)
	}

	return res, err
}

// RESTMapping implements Mapper.RESTMapping.
func (m *lazyRESTMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	res, err := m.mapper.RESTMapping(gk, versions...)
	if meta.IsNoMatchError(err) {
		if err = m.addKnownGroupAndReload(gk.Group, versions...); err != nil {
			return res, err
		}

		res, err = m.mapper.RESTMapping(gk, versions...)
	}

	return res, err
}

// RESTMappings implements Mapper.RESTMappings.
func (m *lazyRESTMapper) RESTMappings(gk schema.GroupKind, versions ...string) ([]*meta.RESTMapping, error) {
	res, err := m.mapper.RESTMappings(gk, versions...)
	if meta.IsNoMatchError(err) {
		if err = m.addKnownGroupAndReload(gk.Group, versions...); err != nil {
			return res, err
		}

		res, err = m.mapper.RESTMappings(gk, versions...)
	}

	return res, err
}

// ResourceSingularizer implements Mapper.ResourceSingularizer.
func (m *lazyRESTMapper) ResourceSingularizer(resource string) (string, error) {
	return m.mapper.ResourceSingularizer(resource)
}

// addKnownGroupAndReload reloads the mapper with updated information about missing API group.
// versions can be specified for partial updates, for instance for v1beta1 version only.
func (m *lazyRESTMapper) addKnownGroupAndReload(groupName string, versions ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If no specific versions are set by user, we will scan all available ones for the API group.
	// This operation requires 2 requests: /api and /apis, but only once. For all subsequent calls
	// this data will be taken from cache.
	if len(versions) == 0 {
		apiGroup, err := m.findAPIGroupByNameLocked(groupName)
		if err != nil {
			return err
		}
		for _, version := range apiGroup.Versions {
			versions = append(versions, version.Version)
		}
	}

	// Create or fetch group resources from cache.
	groupResources := &restmapper.APIGroupResources{
		Group:              metav1.APIGroup{Name: groupName},
		VersionedResources: make(map[string][]metav1.APIResource),
	}
	if _, ok := m.knownGroups[groupName]; ok {
		groupResources = m.knownGroups[groupName]
	}

	// Update information for group resources about versioned resources.
	// The number of API calls is equal to the number of versions: /apis/<group>/<version>.
	groupVersionResources, err := m.fetchGroupVersionResources(groupName, versions...)
	if err != nil {
		return fmt.Errorf("failed to get API group resources: %w", err)
	}
	for version, resources := range groupVersionResources {
		groupResources.VersionedResources[version.Version] = resources.APIResources
	}

	// Update information for group resources about the API group by adding new versions.
	// Ignore the versions that are already registered.
	for _, version := range versions {
		found := false
		for _, v := range groupResources.Group.Versions {
			if v.Version == version {
				found = true
				break
			}
		}

		if !found {
			groupResources.Group.Versions = append(groupResources.Group.Versions, metav1.GroupVersionForDiscovery{
				GroupVersion: metav1.GroupVersion{Group: groupName, Version: version}.String(),
				Version:      version,
			})
		}
	}

	// Update data in the cache.
	m.knownGroups[groupName] = groupResources

	// Finally, update the group with received information and regenerate the mapper.
	updatedGroupResources := make([]*restmapper.APIGroupResources, 0, len(m.knownGroups))
	for _, agr := range m.knownGroups {
		updatedGroupResources = append(updatedGroupResources, agr)
	}

	m.mapper = restmapper.NewDiscoveryRESTMapper(updatedGroupResources)

	return nil
}

// findAPIGroupByNameLocked returns API group by its name.
func (m *lazyRESTMapper) findAPIGroupByNameLocked(groupName string) (metav1.APIGroup, error) {
	// Looking in the cache first.
	for _, apiGroup := range m.apiGroups {
		if groupName == apiGroup.Name {
			return apiGroup, nil
		}
	}

	// Update the cache if nothing was found.
	apiGroups, err := m.client.ServerGroups()
	if err != nil {
		return metav1.APIGroup{}, fmt.Errorf("failed to get server groups: %w", err)
	}
	if len(apiGroups.Groups) == 0 {
		return metav1.APIGroup{}, fmt.Errorf("received an empty API groups list")
	}

	m.apiGroups = apiGroups.Groups

	// Looking in the cache again.
	for _, apiGroup := range m.apiGroups {
		if groupName == apiGroup.Name {
			return apiGroup, nil
		}
	}

	// If there is still nothing, return an error.
	return metav1.APIGroup{}, fmt.Errorf("failed to find API group %s", groupName)
}

// fetchGroupVersionResources fetches the resources for the specified group and its versions.
func (m *lazyRESTMapper) fetchGroupVersionResources(groupName string, versions ...string) (map[schema.GroupVersion]*metav1.APIResourceList, error) {
	groupVersionResources := make(map[schema.GroupVersion]*metav1.APIResourceList)
	failedGroups := make(map[schema.GroupVersion]error)

	for _, version := range versions {
		groupVersion := schema.GroupVersion{Group: groupName, Version: version}

		apiResourceList, err := m.client.ServerResourcesForGroupVersion(groupVersion.String())
		if err != nil {
			failedGroups[groupVersion] = err
		}
		if apiResourceList != nil {
			// even in case of error, some fallback might have been returned.
			groupVersionResources[groupVersion] = apiResourceList
		}
	}

	if len(failedGroups) > 0 {
		return nil, &discovery.ErrGroupDiscoveryFailed{Groups: failedGroups}
	}

	return groupVersionResources, nil
}
