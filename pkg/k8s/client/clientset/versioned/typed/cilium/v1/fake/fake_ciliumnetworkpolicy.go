// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fake

import (
	cilium_io_v1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCiliumNetworkPolicies implements CiliumNetworkPolicyInterface
type FakeCiliumNetworkPolicies struct {
	Fake *FakeCiliumV1
	ns   string
}

var ciliumnetworkpoliciesResource = schema.GroupVersionResource{Group: "cilium.io", Version: "v1", Resource: "ciliumnetworkpolicies"}

var ciliumnetworkpoliciesKind = schema.GroupVersionKind{Group: "cilium.io", Version: "v1", Kind: "CiliumNetworkPolicy"}

// Get takes name of the ciliumNetworkPolicy, and returns the corresponding ciliumNetworkPolicy object, and an error if there is any.
func (c *FakeCiliumNetworkPolicies) Get(name string, options v1.GetOptions) (result *cilium_io_v1.CiliumNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(ciliumnetworkpoliciesResource, c.ns, name), &cilium_io_v1.CiliumNetworkPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*cilium_io_v1.CiliumNetworkPolicy), err
}

// List takes label and field selectors, and returns the list of CiliumNetworkPolicies that match those selectors.
func (c *FakeCiliumNetworkPolicies) List(opts v1.ListOptions) (result *cilium_io_v1.CiliumNetworkPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(ciliumnetworkpoliciesResource, ciliumnetworkpoliciesKind, c.ns, opts), &cilium_io_v1.CiliumNetworkPolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &cilium_io_v1.CiliumNetworkPolicyList{}
	for _, item := range obj.(*cilium_io_v1.CiliumNetworkPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ciliumNetworkPolicies.
func (c *FakeCiliumNetworkPolicies) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(ciliumnetworkpoliciesResource, c.ns, opts))

}

// Create takes the representation of a ciliumNetworkPolicy and creates it.  Returns the server's representation of the ciliumNetworkPolicy, and an error, if there is any.
func (c *FakeCiliumNetworkPolicies) Create(ciliumNetworkPolicy *cilium_io_v1.CiliumNetworkPolicy) (result *cilium_io_v1.CiliumNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(ciliumnetworkpoliciesResource, c.ns, ciliumNetworkPolicy), &cilium_io_v1.CiliumNetworkPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*cilium_io_v1.CiliumNetworkPolicy), err
}

// Update takes the representation of a ciliumNetworkPolicy and updates it. Returns the server's representation of the ciliumNetworkPolicy, and an error, if there is any.
func (c *FakeCiliumNetworkPolicies) Update(ciliumNetworkPolicy *cilium_io_v1.CiliumNetworkPolicy) (result *cilium_io_v1.CiliumNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(ciliumnetworkpoliciesResource, c.ns, ciliumNetworkPolicy), &cilium_io_v1.CiliumNetworkPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*cilium_io_v1.CiliumNetworkPolicy), err
}

// Delete takes name of the ciliumNetworkPolicy and deletes it. Returns an error if one occurs.
func (c *FakeCiliumNetworkPolicies) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(ciliumnetworkpoliciesResource, c.ns, name), &cilium_io_v1.CiliumNetworkPolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCiliumNetworkPolicies) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(ciliumnetworkpoliciesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &cilium_io_v1.CiliumNetworkPolicyList{})
	return err
}

// Patch applies the patch and returns the patched ciliumNetworkPolicy.
func (c *FakeCiliumNetworkPolicies) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *cilium_io_v1.CiliumNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(ciliumnetworkpoliciesResource, c.ns, name, data, subresources...), &cilium_io_v1.CiliumNetworkPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*cilium_io_v1.CiliumNetworkPolicy), err
}
