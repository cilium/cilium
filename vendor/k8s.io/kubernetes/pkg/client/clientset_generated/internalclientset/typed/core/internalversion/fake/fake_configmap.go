/*
Copyright 2017 The Kubernetes Authors.

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

package fake

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	api "k8s.io/kubernetes/pkg/api"
)

// FakeConfigMaps implements ConfigMapInterface
type FakeConfigMaps struct {
	Fake *FakeCore
	ns   string
}

var configmapsResource = schema.GroupVersionResource{Group: "", Version: "", Resource: "configmaps"}

var configmapsKind = schema.GroupVersionKind{Group: "", Version: "", Kind: "ConfigMap"}

// Get takes name of the configMap, and returns the corresponding configMap object, and an error if there is any.
func (c *FakeConfigMaps) Get(name string, options v1.GetOptions) (result *api.ConfigMap, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(configmapsResource, c.ns, name), &api.ConfigMap{})

	if obj == nil {
		return nil, err
	}
	return obj.(*api.ConfigMap), err
}

// List takes label and field selectors, and returns the list of ConfigMaps that match those selectors.
func (c *FakeConfigMaps) List(opts v1.ListOptions) (result *api.ConfigMapList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(configmapsResource, configmapsKind, c.ns, opts), &api.ConfigMapList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &api.ConfigMapList{}
	for _, item := range obj.(*api.ConfigMapList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested configMaps.
func (c *FakeConfigMaps) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(configmapsResource, c.ns, opts))

}

// Create takes the representation of a configMap and creates it.  Returns the server's representation of the configMap, and an error, if there is any.
func (c *FakeConfigMaps) Create(configMap *api.ConfigMap) (result *api.ConfigMap, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(configmapsResource, c.ns, configMap), &api.ConfigMap{})

	if obj == nil {
		return nil, err
	}
	return obj.(*api.ConfigMap), err
}

// Update takes the representation of a configMap and updates it. Returns the server's representation of the configMap, and an error, if there is any.
func (c *FakeConfigMaps) Update(configMap *api.ConfigMap) (result *api.ConfigMap, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(configmapsResource, c.ns, configMap), &api.ConfigMap{})

	if obj == nil {
		return nil, err
	}
	return obj.(*api.ConfigMap), err
}

// Delete takes name of the configMap and deletes it. Returns an error if one occurs.
func (c *FakeConfigMaps) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(configmapsResource, c.ns, name), &api.ConfigMap{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeConfigMaps) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(configmapsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &api.ConfigMapList{})
	return err
}

// Patch applies the patch and returns the patched configMap.
func (c *FakeConfigMaps) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *api.ConfigMap, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(configmapsResource, c.ns, name, data, subresources...), &api.ConfigMap{})

	if obj == nil {
		return nil, err
	}
	return obj.(*api.ConfigMap), err
}
