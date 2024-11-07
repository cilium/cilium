/*
Copyright 2024 The Kubernetes Authors.

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

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// WithFieldValidation wraps a Client and configures field validation, by
// default, for all write requests from this client. Users can override field
// validation for individual write requests.
func WithFieldValidation(c Client, validation FieldValidation) Client {
	return &clientWithFieldValidation{
		validation: validation,
		client:     c,
		Reader:     c,
	}
}

type clientWithFieldValidation struct {
	validation FieldValidation
	client     Client
	Reader
}

func (c *clientWithFieldValidation) Create(ctx context.Context, obj Object, opts ...CreateOption) error {
	return c.client.Create(ctx, obj, append([]CreateOption{c.validation}, opts...)...)
}

func (c *clientWithFieldValidation) Update(ctx context.Context, obj Object, opts ...UpdateOption) error {
	return c.client.Update(ctx, obj, append([]UpdateOption{c.validation}, opts...)...)
}

func (c *clientWithFieldValidation) Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error {
	return c.client.Patch(ctx, obj, patch, append([]PatchOption{c.validation}, opts...)...)
}

func (c *clientWithFieldValidation) Delete(ctx context.Context, obj Object, opts ...DeleteOption) error {
	return c.client.Delete(ctx, obj, opts...)
}

func (c *clientWithFieldValidation) DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error {
	return c.client.DeleteAllOf(ctx, obj, opts...)
}

func (c *clientWithFieldValidation) Scheme() *runtime.Scheme     { return c.client.Scheme() }
func (c *clientWithFieldValidation) RESTMapper() meta.RESTMapper { return c.client.RESTMapper() }
func (c *clientWithFieldValidation) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return c.client.GroupVersionKindFor(obj)
}

func (c *clientWithFieldValidation) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return c.client.IsObjectNamespaced(obj)
}

func (c *clientWithFieldValidation) Status() StatusWriter {
	return &subresourceClientWithFieldValidation{
		validation:        c.validation,
		subresourceWriter: c.client.Status(),
	}
}

func (c *clientWithFieldValidation) SubResource(subresource string) SubResourceClient {
	srClient := c.client.SubResource(subresource)
	return &subresourceClientWithFieldValidation{
		validation:        c.validation,
		subresourceWriter: srClient,
		SubResourceReader: srClient,
	}
}

type subresourceClientWithFieldValidation struct {
	validation        FieldValidation
	subresourceWriter SubResourceWriter
	SubResourceReader
}

func (c *subresourceClientWithFieldValidation) Create(ctx context.Context, obj Object, subresource Object, opts ...SubResourceCreateOption) error {
	return c.subresourceWriter.Create(ctx, obj, subresource, append([]SubResourceCreateOption{c.validation}, opts...)...)
}

func (c *subresourceClientWithFieldValidation) Update(ctx context.Context, obj Object, opts ...SubResourceUpdateOption) error {
	return c.subresourceWriter.Update(ctx, obj, append([]SubResourceUpdateOption{c.validation}, opts...)...)
}

func (c *subresourceClientWithFieldValidation) Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourcePatchOption) error {
	return c.subresourceWriter.Patch(ctx, obj, patch, append([]SubResourcePatchOption{c.validation}, opts...)...)
}
