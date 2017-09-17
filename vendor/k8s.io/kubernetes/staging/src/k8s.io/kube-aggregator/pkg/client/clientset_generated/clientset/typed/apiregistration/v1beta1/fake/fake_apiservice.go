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
	v1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

// FakeAPIServices implements APIServiceInterface
type FakeAPIServices struct {
	Fake *FakeApiregistrationV1beta1
}

var apiservicesResource = schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1beta1", Resource: "apiservices"}

var apiservicesKind = schema.GroupVersionKind{Group: "apiregistration.k8s.io", Version: "v1beta1", Kind: "APIService"}

// Get takes name of the aPIService, and returns the corresponding aPIService object, and an error if there is any.
func (c *FakeAPIServices) Get(name string, options v1.GetOptions) (result *v1beta1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(apiservicesResource, name), &v1beta1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.APIService), err
}

// List takes label and field selectors, and returns the list of APIServices that match those selectors.
func (c *FakeAPIServices) List(opts v1.ListOptions) (result *v1beta1.APIServiceList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(apiservicesResource, apiservicesKind, opts), &v1beta1.APIServiceList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.APIServiceList{}
	for _, item := range obj.(*v1beta1.APIServiceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested aPIServices.
func (c *FakeAPIServices) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(apiservicesResource, opts))
}

// Create takes the representation of a aPIService and creates it.  Returns the server's representation of the aPIService, and an error, if there is any.
func (c *FakeAPIServices) Create(aPIService *v1beta1.APIService) (result *v1beta1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(apiservicesResource, aPIService), &v1beta1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.APIService), err
}

// Update takes the representation of a aPIService and updates it. Returns the server's representation of the aPIService, and an error, if there is any.
func (c *FakeAPIServices) Update(aPIService *v1beta1.APIService) (result *v1beta1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(apiservicesResource, aPIService), &v1beta1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.APIService), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeAPIServices) UpdateStatus(aPIService *v1beta1.APIService) (*v1beta1.APIService, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(apiservicesResource, "status", aPIService), &v1beta1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.APIService), err
}

// Delete takes name of the aPIService and deletes it. Returns an error if one occurs.
func (c *FakeAPIServices) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(apiservicesResource, name), &v1beta1.APIService{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeAPIServices) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(apiservicesResource, listOptions)

	_, err := c.Fake.Invokes(action, &v1beta1.APIServiceList{})
	return err
}

// Patch applies the patch and returns the patched aPIService.
func (c *FakeAPIServices) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1beta1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(apiservicesResource, name, data, subresources...), &v1beta1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.APIService), err
}
