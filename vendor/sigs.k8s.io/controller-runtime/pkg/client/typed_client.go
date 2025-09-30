/*
Copyright 2018 The Kubernetes Authors.

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

package client

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/apply"
)

var _ Reader = &typedClient{}
var _ Writer = &typedClient{}

type typedClient struct {
	resources  *clientRestResources
	paramCodec runtime.ParameterCodec
}

// Create implements client.Client.
func (c *typedClient) Create(ctx context.Context, obj Object, opts ...CreateOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	createOpts := &CreateOptions{}
	createOpts.ApplyOptions(opts)

	return o.Post().
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Body(obj).
		VersionedParams(createOpts.AsCreateOptions(), c.paramCodec).
		Do(ctx).
		Into(obj)
}

// Update implements client.Client.
func (c *typedClient) Update(ctx context.Context, obj Object, opts ...UpdateOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	updateOpts := &UpdateOptions{}
	updateOpts.ApplyOptions(opts)

	return o.Put().
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		Body(obj).
		VersionedParams(updateOpts.AsUpdateOptions(), c.paramCodec).
		Do(ctx).
		Into(obj)
}

// Delete implements client.Client.
func (c *typedClient) Delete(ctx context.Context, obj Object, opts ...DeleteOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	deleteOpts := DeleteOptions{}
	deleteOpts.ApplyOptions(opts)

	return o.Delete().
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		Body(deleteOpts.AsDeleteOptions()).
		Do(ctx).
		Error()
}

// DeleteAllOf implements client.Client.
func (c *typedClient) DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	deleteAllOfOpts := DeleteAllOfOptions{}
	deleteAllOfOpts.ApplyOptions(opts)

	return o.Delete().
		NamespaceIfScoped(deleteAllOfOpts.ListOptions.Namespace, o.isNamespaced()).
		Resource(o.resource()).
		VersionedParams(deleteAllOfOpts.AsListOptions(), c.paramCodec).
		Body(deleteAllOfOpts.AsDeleteOptions()).
		Do(ctx).
		Error()
}

// Patch implements client.Client.
func (c *typedClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	data, err := patch.Data(obj)
	if err != nil {
		return err
	}

	patchOpts := &PatchOptions{}
	patchOpts.ApplyOptions(opts)

	return o.Patch(patch.Type()).
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		VersionedParams(patchOpts.AsPatchOptions(), c.paramCodec).
		Body(data).
		Do(ctx).
		Into(obj)
}

func (c *typedClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...ApplyOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}
	req, err := apply.NewRequest(o, obj)
	if err != nil {
		return fmt.Errorf("failed to create apply request: %w", err)
	}
	applyOpts := &ApplyOptions{}
	applyOpts.ApplyOptions(opts)

	return req.
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		VersionedParams(applyOpts.AsPatchOptions(), c.paramCodec).
		Do(ctx).
		// This is hacky, it is required because `Into` takes a `runtime.Object` and
		// that is not implemented by the ApplyConfigurations. The generated clients
		// don't have this problem because they deserialize into the api type, not the
		// apply configuration: https://github.com/kubernetes/kubernetes/blob/22f5e01a37c0bc6a5f494dec14dd4e3688ee1d55/staging/src/k8s.io/client-go/gentype/type.go#L296-L317
		Into(runtimeObjectFromApplyConfiguration(obj))
}

// Get implements client.Client.
func (c *typedClient) Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) error {
	r, err := c.resources.getResource(obj)
	if err != nil {
		return err
	}
	getOpts := GetOptions{}
	getOpts.ApplyOptions(opts)
	return r.Get().
		NamespaceIfScoped(key.Namespace, r.isNamespaced()).
		Resource(r.resource()).
		VersionedParams(getOpts.AsGetOptions(), c.paramCodec).
		Name(key.Name).Do(ctx).Into(obj)
}

// List implements client.Client.
func (c *typedClient) List(ctx context.Context, obj ObjectList, opts ...ListOption) error {
	r, err := c.resources.getResource(obj)
	if err != nil {
		return err
	}

	listOpts := ListOptions{}
	listOpts.ApplyOptions(opts)

	return r.Get().
		NamespaceIfScoped(listOpts.Namespace, r.isNamespaced()).
		Resource(r.resource()).
		VersionedParams(listOpts.AsListOptions(), c.paramCodec).
		Do(ctx).
		Into(obj)
}

func (c *typedClient) GetSubResource(ctx context.Context, obj, subResourceObj Object, subResource string, opts ...SubResourceGetOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	if subResourceObj.GetName() == "" {
		subResourceObj.SetName(obj.GetName())
	}

	getOpts := &SubResourceGetOptions{}
	getOpts.ApplyOptions(opts)

	return o.Get().
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		SubResource(subResource).
		VersionedParams(getOpts.AsGetOptions(), c.paramCodec).
		Do(ctx).
		Into(subResourceObj)
}

func (c *typedClient) CreateSubResource(ctx context.Context, obj Object, subResourceObj Object, subResource string, opts ...SubResourceCreateOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	if subResourceObj.GetName() == "" {
		subResourceObj.SetName(obj.GetName())
	}

	createOpts := &SubResourceCreateOptions{}
	createOpts.ApplyOptions(opts)

	return o.Post().
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		SubResource(subResource).
		Body(subResourceObj).
		VersionedParams(createOpts.AsCreateOptions(), c.paramCodec).
		Do(ctx).
		Into(subResourceObj)
}

// UpdateSubResource used by SubResourceWriter to write status.
func (c *typedClient) UpdateSubResource(ctx context.Context, obj Object, subResource string, opts ...SubResourceUpdateOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}
	// TODO(droot): examine the returned error and check if it error needs to be
	// wrapped to improve the UX ?
	// It will be nice to receive an error saying the object doesn't implement
	// status subresource and check CRD definition
	updateOpts := &SubResourceUpdateOptions{}
	updateOpts.ApplyOptions(opts)

	body := obj
	if updateOpts.SubResourceBody != nil {
		body = updateOpts.SubResourceBody
	}
	if body.GetName() == "" {
		body.SetName(obj.GetName())
	}
	if body.GetNamespace() == "" {
		body.SetNamespace(obj.GetNamespace())
	}

	return o.Put().
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		SubResource(subResource).
		Body(body).
		VersionedParams(updateOpts.AsUpdateOptions(), c.paramCodec).
		Do(ctx).
		Into(body)
}

// PatchSubResource used by SubResourceWriter to write subresource.
func (c *typedClient) PatchSubResource(ctx context.Context, obj Object, subResource string, patch Patch, opts ...SubResourcePatchOption) error {
	o, err := c.resources.getObjMeta(obj)
	if err != nil {
		return err
	}

	patchOpts := &SubResourcePatchOptions{}
	patchOpts.ApplyOptions(opts)

	body := obj
	if patchOpts.SubResourceBody != nil {
		body = patchOpts.SubResourceBody
	}

	data, err := patch.Data(body)
	if err != nil {
		return err
	}

	return o.Patch(patch.Type()).
		NamespaceIfScoped(o.namespace, o.isNamespaced()).
		Resource(o.resource()).
		Name(o.name).
		SubResource(subResource).
		Body(data).
		VersionedParams(patchOpts.AsPatchOptions(), c.paramCodec).
		Do(ctx).
		Into(body)
}
