/*
Copyright 2016 The Kubernetes Authors.

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

package storage

import (
	"k8s.io/apimachinery/pkg/apimachinery/registered"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ResourceEncodingConfig interface {
	// StorageEncoding returns the serialization format for the resource.
	// TODO this should actually return a GroupVersionKind since you can logically have multiple "matching" Kinds
	// For now, it returns just the GroupVersion for consistency with old behavior
	StorageEncodingFor(schema.GroupResource) (schema.GroupVersion, error)

	// InMemoryEncodingFor returns the groupVersion for the in memory representation the storage should convert to.
	InMemoryEncodingFor(schema.GroupResource) (schema.GroupVersion, error)
}

type DefaultResourceEncodingConfig struct {
	groups   map[string]*GroupResourceEncodingConfig
	registry *registered.APIRegistrationManager
}

type GroupResourceEncodingConfig struct {
	DefaultExternalEncoding   schema.GroupVersion
	ExternalResourceEncodings map[string]schema.GroupVersion

	DefaultInternalEncoding   schema.GroupVersion
	InternalResourceEncodings map[string]schema.GroupVersion
}

var _ ResourceEncodingConfig = &DefaultResourceEncodingConfig{}

func NewDefaultResourceEncodingConfig(registry *registered.APIRegistrationManager) *DefaultResourceEncodingConfig {
	return &DefaultResourceEncodingConfig{groups: map[string]*GroupResourceEncodingConfig{}, registry: registry}
}

func newGroupResourceEncodingConfig(defaultEncoding, defaultInternalVersion schema.GroupVersion) *GroupResourceEncodingConfig {
	return &GroupResourceEncodingConfig{
		DefaultExternalEncoding: defaultEncoding, ExternalResourceEncodings: map[string]schema.GroupVersion{},
		DefaultInternalEncoding: defaultInternalVersion, InternalResourceEncodings: map[string]schema.GroupVersion{},
	}
}

func (o *DefaultResourceEncodingConfig) SetVersionEncoding(group string, externalEncodingVersion, internalVersion schema.GroupVersion) {
	_, groupExists := o.groups[group]
	if !groupExists {
		o.groups[group] = newGroupResourceEncodingConfig(externalEncodingVersion, internalVersion)
	}

	o.groups[group].DefaultExternalEncoding = externalEncodingVersion
	o.groups[group].DefaultInternalEncoding = internalVersion
}

func (o *DefaultResourceEncodingConfig) SetResourceEncoding(resourceBeingStored schema.GroupResource, externalEncodingVersion, internalVersion schema.GroupVersion) {
	group := resourceBeingStored.Group
	_, groupExists := o.groups[group]
	if !groupExists {
		o.groups[group] = newGroupResourceEncodingConfig(externalEncodingVersion, internalVersion)
	}

	o.groups[group].ExternalResourceEncodings[resourceBeingStored.Resource] = externalEncodingVersion
	o.groups[group].InternalResourceEncodings[resourceBeingStored.Resource] = internalVersion
}

func (o *DefaultResourceEncodingConfig) StorageEncodingFor(resource schema.GroupResource) (schema.GroupVersion, error) {
	groupMeta, err := o.registry.Group(resource.Group)
	if err != nil {
		return schema.GroupVersion{}, err
	}

	groupEncoding, groupExists := o.groups[resource.Group]

	if !groupExists {
		// return the most preferred external version for the group
		return groupMeta.GroupVersion, nil
	}

	resourceOverride, resourceExists := groupEncoding.ExternalResourceEncodings[resource.Resource]
	if !resourceExists {
		return groupEncoding.DefaultExternalEncoding, nil
	}

	return resourceOverride, nil
}

func (o *DefaultResourceEncodingConfig) InMemoryEncodingFor(resource schema.GroupResource) (schema.GroupVersion, error) {
	if _, err := o.registry.Group(resource.Group); err != nil {
		return schema.GroupVersion{}, err
	}

	groupEncoding, groupExists := o.groups[resource.Group]
	if !groupExists {
		return schema.GroupVersion{Group: resource.Group, Version: runtime.APIVersionInternal}, nil
	}

	resourceOverride, resourceExists := groupEncoding.InternalResourceEncodings[resource.Resource]
	if !resourceExists {
		return groupEncoding.DefaultInternalEncoding, nil
	}

	return resourceOverride, nil
}
