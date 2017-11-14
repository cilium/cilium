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

package v2

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// CiliumNetworkPoliciesGetter has a method to return a CiliumNetworkPolicyInterface.
// A group's client should implement this interface.
type CiliumNetworkPoliciesGetter interface {
	CiliumNetworkPolicies(namespace string) CiliumNetworkPolicyInterface
}

// CiliumNetworkPolicyInterface has methods to work with CiliumNetworkPolicy resources.
type CiliumNetworkPolicyInterface interface {
	Create(*v2.CiliumNetworkPolicy) (*v2.CiliumNetworkPolicy, error)
	Update(*v2.CiliumNetworkPolicy) (*v2.CiliumNetworkPolicy, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v2.CiliumNetworkPolicy, error)
	List(opts v1.ListOptions) (*v2.CiliumNetworkPolicyList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v2.CiliumNetworkPolicy, err error)
	CiliumNetworkPolicyExpansion
}

// ciliumNetworkPolicies implements CiliumNetworkPolicyInterface
type ciliumNetworkPolicies struct {
	client rest.Interface
	ns     string
}

// newCiliumNetworkPolicies returns a CiliumNetworkPolicies
func newCiliumNetworkPolicies(c *CiliumV2Client, namespace string) *ciliumNetworkPolicies {
	return &ciliumNetworkPolicies{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the ciliumNetworkPolicy, and returns the corresponding ciliumNetworkPolicy object, and an error if there is any.
func (c *ciliumNetworkPolicies) Get(name string, options v1.GetOptions) (result *v2.CiliumNetworkPolicy, err error) {
	result = &v2.CiliumNetworkPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CiliumNetworkPolicies that match those selectors.
func (c *ciliumNetworkPolicies) List(opts v1.ListOptions) (result *v2.CiliumNetworkPolicyList, err error) {
	result = &v2.CiliumNetworkPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested ciliumNetworkPolicies.
func (c *ciliumNetworkPolicies) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a ciliumNetworkPolicy and creates it.  Returns the server's representation of the ciliumNetworkPolicy, and an error, if there is any.
func (c *ciliumNetworkPolicies) Create(ciliumNetworkPolicy *v2.CiliumNetworkPolicy) (result *v2.CiliumNetworkPolicy, err error) {
	result = &v2.CiliumNetworkPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		Body(ciliumNetworkPolicy).
		Do().
		Into(result)
	return
}

// Update takes the representation of a ciliumNetworkPolicy and updates it. Returns the server's representation of the ciliumNetworkPolicy, and an error, if there is any.
func (c *ciliumNetworkPolicies) Update(ciliumNetworkPolicy *v2.CiliumNetworkPolicy) (result *v2.CiliumNetworkPolicy, err error) {
	result = &v2.CiliumNetworkPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		Name(ciliumNetworkPolicy.Name).
		Body(ciliumNetworkPolicy).
		Do().
		Into(result)
	return
}

// Delete takes name of the ciliumNetworkPolicy and deletes it. Returns an error if one occurs.
func (c *ciliumNetworkPolicies) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *ciliumNetworkPolicies) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched ciliumNetworkPolicy.
func (c *ciliumNetworkPolicies) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v2.CiliumNetworkPolicy, err error) {
	result = &v2.CiliumNetworkPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("ciliumnetworkpolicies").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
