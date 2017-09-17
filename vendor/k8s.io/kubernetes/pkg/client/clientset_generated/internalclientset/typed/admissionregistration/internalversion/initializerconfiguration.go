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
	admissionregistration "k8s.io/kubernetes/pkg/apis/admissionregistration"
	scheme "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/scheme"
)

// InitializerConfigurationsGetter has a method to return a InitializerConfigurationInterface.
// A group's client should implement this interface.
type InitializerConfigurationsGetter interface {
	InitializerConfigurations() InitializerConfigurationInterface
}

// InitializerConfigurationInterface has methods to work with InitializerConfiguration resources.
type InitializerConfigurationInterface interface {
	Create(*admissionregistration.InitializerConfiguration) (*admissionregistration.InitializerConfiguration, error)
	Update(*admissionregistration.InitializerConfiguration) (*admissionregistration.InitializerConfiguration, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*admissionregistration.InitializerConfiguration, error)
	List(opts v1.ListOptions) (*admissionregistration.InitializerConfigurationList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *admissionregistration.InitializerConfiguration, err error)
	InitializerConfigurationExpansion
}

// initializerConfigurations implements InitializerConfigurationInterface
type initializerConfigurations struct {
	client rest.Interface
}

// newInitializerConfigurations returns a InitializerConfigurations
func newInitializerConfigurations(c *AdmissionregistrationClient) *initializerConfigurations {
	return &initializerConfigurations{
		client: c.RESTClient(),
	}
}

// Get takes name of the initializerConfiguration, and returns the corresponding initializerConfiguration object, and an error if there is any.
func (c *initializerConfigurations) Get(name string, options v1.GetOptions) (result *admissionregistration.InitializerConfiguration, err error) {
	result = &admissionregistration.InitializerConfiguration{}
	err = c.client.Get().
		Resource("initializerconfigurations").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of InitializerConfigurations that match those selectors.
func (c *initializerConfigurations) List(opts v1.ListOptions) (result *admissionregistration.InitializerConfigurationList, err error) {
	result = &admissionregistration.InitializerConfigurationList{}
	err = c.client.Get().
		Resource("initializerconfigurations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested initializerConfigurations.
func (c *initializerConfigurations) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Resource("initializerconfigurations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a initializerConfiguration and creates it.  Returns the server's representation of the initializerConfiguration, and an error, if there is any.
func (c *initializerConfigurations) Create(initializerConfiguration *admissionregistration.InitializerConfiguration) (result *admissionregistration.InitializerConfiguration, err error) {
	result = &admissionregistration.InitializerConfiguration{}
	err = c.client.Post().
		Resource("initializerconfigurations").
		Body(initializerConfiguration).
		Do().
		Into(result)
	return
}

// Update takes the representation of a initializerConfiguration and updates it. Returns the server's representation of the initializerConfiguration, and an error, if there is any.
func (c *initializerConfigurations) Update(initializerConfiguration *admissionregistration.InitializerConfiguration) (result *admissionregistration.InitializerConfiguration, err error) {
	result = &admissionregistration.InitializerConfiguration{}
	err = c.client.Put().
		Resource("initializerconfigurations").
		Name(initializerConfiguration.Name).
		Body(initializerConfiguration).
		Do().
		Into(result)
	return
}

// Delete takes name of the initializerConfiguration and deletes it. Returns an error if one occurs.
func (c *initializerConfigurations) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("initializerconfigurations").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *initializerConfigurations) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Resource("initializerconfigurations").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched initializerConfiguration.
func (c *initializerConfigurations) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *admissionregistration.InitializerConfiguration, err error) {
	result = &admissionregistration.InitializerConfiguration{}
	err = c.client.Patch(pt).
		Resource("initializerconfigurations").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
