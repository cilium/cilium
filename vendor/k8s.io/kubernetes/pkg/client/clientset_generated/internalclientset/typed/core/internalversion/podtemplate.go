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
	api "k8s.io/kubernetes/pkg/api"
	scheme "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/scheme"
)

// PodTemplatesGetter has a method to return a PodTemplateInterface.
// A group's client should implement this interface.
type PodTemplatesGetter interface {
	PodTemplates(namespace string) PodTemplateInterface
}

// PodTemplateInterface has methods to work with PodTemplate resources.
type PodTemplateInterface interface {
	Create(*api.PodTemplate) (*api.PodTemplate, error)
	Update(*api.PodTemplate) (*api.PodTemplate, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*api.PodTemplate, error)
	List(opts v1.ListOptions) (*api.PodTemplateList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *api.PodTemplate, err error)
	PodTemplateExpansion
}

// podTemplates implements PodTemplateInterface
type podTemplates struct {
	client rest.Interface
	ns     string
}

// newPodTemplates returns a PodTemplates
func newPodTemplates(c *CoreClient, namespace string) *podTemplates {
	return &podTemplates{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the podTemplate, and returns the corresponding podTemplate object, and an error if there is any.
func (c *podTemplates) Get(name string, options v1.GetOptions) (result *api.PodTemplate, err error) {
	result = &api.PodTemplate{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("podtemplates").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of PodTemplates that match those selectors.
func (c *podTemplates) List(opts v1.ListOptions) (result *api.PodTemplateList, err error) {
	result = &api.PodTemplateList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("podtemplates").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested podTemplates.
func (c *podTemplates) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("podtemplates").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a podTemplate and creates it.  Returns the server's representation of the podTemplate, and an error, if there is any.
func (c *podTemplates) Create(podTemplate *api.PodTemplate) (result *api.PodTemplate, err error) {
	result = &api.PodTemplate{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("podtemplates").
		Body(podTemplate).
		Do().
		Into(result)
	return
}

// Update takes the representation of a podTemplate and updates it. Returns the server's representation of the podTemplate, and an error, if there is any.
func (c *podTemplates) Update(podTemplate *api.PodTemplate) (result *api.PodTemplate, err error) {
	result = &api.PodTemplate{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("podtemplates").
		Name(podTemplate.Name).
		Body(podTemplate).
		Do().
		Into(result)
	return
}

// Delete takes name of the podTemplate and deletes it. Returns an error if one occurs.
func (c *podTemplates) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("podtemplates").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *podTemplates) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("podtemplates").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched podTemplate.
func (c *podTemplates) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *api.PodTemplate, err error) {
	result = &api.PodTemplate{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("podtemplates").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
