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
	extensions "k8s.io/kubernetes/pkg/apis/extensions"
)

// FakeIngresses implements IngressInterface
type FakeIngresses struct {
	Fake *FakeExtensions
	ns   string
}

var ingressesResource = schema.GroupVersionResource{Group: "extensions", Version: "", Resource: "ingresses"}

var ingressesKind = schema.GroupVersionKind{Group: "extensions", Version: "", Kind: "Ingress"}

// Get takes name of the ingress, and returns the corresponding ingress object, and an error if there is any.
func (c *FakeIngresses) Get(name string, options v1.GetOptions) (result *extensions.Ingress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(ingressesResource, c.ns, name), &extensions.Ingress{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.Ingress), err
}

// List takes label and field selectors, and returns the list of Ingresses that match those selectors.
func (c *FakeIngresses) List(opts v1.ListOptions) (result *extensions.IngressList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(ingressesResource, ingressesKind, c.ns, opts), &extensions.IngressList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &extensions.IngressList{}
	for _, item := range obj.(*extensions.IngressList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ingresses.
func (c *FakeIngresses) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(ingressesResource, c.ns, opts))

}

// Create takes the representation of a ingress and creates it.  Returns the server's representation of the ingress, and an error, if there is any.
func (c *FakeIngresses) Create(ingress *extensions.Ingress) (result *extensions.Ingress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(ingressesResource, c.ns, ingress), &extensions.Ingress{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.Ingress), err
}

// Update takes the representation of a ingress and updates it. Returns the server's representation of the ingress, and an error, if there is any.
func (c *FakeIngresses) Update(ingress *extensions.Ingress) (result *extensions.Ingress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(ingressesResource, c.ns, ingress), &extensions.Ingress{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.Ingress), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeIngresses) UpdateStatus(ingress *extensions.Ingress) (*extensions.Ingress, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(ingressesResource, "status", c.ns, ingress), &extensions.Ingress{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.Ingress), err
}

// Delete takes name of the ingress and deletes it. Returns an error if one occurs.
func (c *FakeIngresses) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(ingressesResource, c.ns, name), &extensions.Ingress{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIngresses) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(ingressesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &extensions.IngressList{})
	return err
}

// Patch applies the patch and returns the patched ingress.
func (c *FakeIngresses) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *extensions.Ingress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(ingressesResource, c.ns, name, data, subresources...), &extensions.Ingress{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.Ingress), err
}
