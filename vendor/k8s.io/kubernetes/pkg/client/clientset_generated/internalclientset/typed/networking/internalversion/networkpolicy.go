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

package internalversion

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	networking "k8s.io/kubernetes/pkg/apis/networking"
	scheme "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/scheme"
)

// NetworkPoliciesGetter has a method to return a NetworkPolicyInterface.
// A group's client should implement this interface.
type NetworkPoliciesGetter interface {
	NetworkPolicies(namespace string) NetworkPolicyInterface
}

// NetworkPolicyInterface has methods to work with NetworkPolicy resources.
type NetworkPolicyInterface interface {
	Create(*networking.NetworkPolicy) (*networking.NetworkPolicy, error)
	Update(*networking.NetworkPolicy) (*networking.NetworkPolicy, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*networking.NetworkPolicy, error)
	List(opts v1.ListOptions) (*networking.NetworkPolicyList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *networking.NetworkPolicy, err error)
	NetworkPolicyExpansion
}

// networkPolicies implements NetworkPolicyInterface
type networkPolicies struct {
	client rest.Interface
	ns     string
}

// newNetworkPolicies returns a NetworkPolicies
func newNetworkPolicies(c *NetworkingClient, namespace string) *networkPolicies {
	return &networkPolicies{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the networkPolicy, and returns the corresponding networkPolicy object, and an error if there is any.
func (c *networkPolicies) Get(name string, options v1.GetOptions) (result *networking.NetworkPolicy, err error) {
	result = &networking.NetworkPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("networkpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of NetworkPolicies that match those selectors.
func (c *networkPolicies) List(opts v1.ListOptions) (result *networking.NetworkPolicyList, err error) {
	result = &networking.NetworkPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("networkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested networkPolicies.
func (c *networkPolicies) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("networkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a networkPolicy and creates it.  Returns the server's representation of the networkPolicy, and an error, if there is any.
func (c *networkPolicies) Create(networkPolicy *networking.NetworkPolicy) (result *networking.NetworkPolicy, err error) {
	result = &networking.NetworkPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("networkpolicies").
		Body(networkPolicy).
		Do().
		Into(result)
	return
}

// Update takes the representation of a networkPolicy and updates it. Returns the server's representation of the networkPolicy, and an error, if there is any.
func (c *networkPolicies) Update(networkPolicy *networking.NetworkPolicy) (result *networking.NetworkPolicy, err error) {
	result = &networking.NetworkPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("networkpolicies").
		Name(networkPolicy.Name).
		Body(networkPolicy).
		Do().
		Into(result)
	return
}

// Delete takes name of the networkPolicy and deletes it. Returns an error if one occurs.
func (c *networkPolicies) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("networkpolicies").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *networkPolicies) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("networkpolicies").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched networkPolicy.
func (c *networkPolicies) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *networking.NetworkPolicy, err error) {
	result = &networking.NetworkPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("networkpolicies").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
