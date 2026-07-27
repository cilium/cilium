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

// WithFieldOwner wraps a Client and adds the fieldOwner as the field
// manager to all write requests from this client. If additional [FieldOwner]
// options are specified on methods of this client, the value specified here
// will be overridden.
func WithFieldOwner(c Client, fieldOwner string) Client {
	return &clientWithFieldManager{
		owner:  fieldOwner,
		c:      c,
		Reader: c,
	}
}

type clientWithFieldManager struct {
	owner string
	c     Client
	Reader
}

func (f *clientWithFieldManager) Create(ctx context.Context, obj Object, opts ...CreateOption) error {
	return f.c.Create(ctx, obj, append([]CreateOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *clientWithFieldManager) Update(ctx context.Context, obj Object, opts ...UpdateOption) error {
	return f.c.Update(ctx, obj, append([]UpdateOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *clientWithFieldManager) Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error {
	return f.c.Patch(ctx, obj, patch, append([]PatchOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *clientWithFieldManager) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...ApplyOption) error {
	return f.c.Apply(ctx, obj, append([]ApplyOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *clientWithFieldManager) Delete(ctx context.Context, obj Object, opts ...DeleteOption) error {
	return f.c.Delete(ctx, obj, opts...)
}

func (f *clientWithFieldManager) DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error {
	return f.c.DeleteAllOf(ctx, obj, opts...)
}

func (f *clientWithFieldManager) Scheme() *runtime.Scheme     { return f.c.Scheme() }
func (f *clientWithFieldManager) RESTMapper() meta.RESTMapper { return f.c.RESTMapper() }
func (f *clientWithFieldManager) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return f.c.GroupVersionKindFor(obj)
}
func (f *clientWithFieldManager) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return f.c.IsObjectNamespaced(obj)
}

func (f *clientWithFieldManager) Status() StatusWriter {
	return &subresourceClientWithFieldOwner{
		owner:             f.owner,
		subresourceWriter: f.c.Status(),
	}
}

func (f *clientWithFieldManager) SubResource(subresource string) SubResourceClient {
	c := f.c.SubResource(subresource)
	return &subresourceClientWithFieldOwner{
		owner:             f.owner,
		subresourceWriter: c,
		SubResourceReader: c,
	}
}

type subresourceClientWithFieldOwner struct {
	owner             string
	subresourceWriter SubResourceWriter
	SubResourceReader
}

func (f *subresourceClientWithFieldOwner) Create(ctx context.Context, obj Object, subresource Object, opts ...SubResourceCreateOption) error {
	return f.subresourceWriter.Create(ctx, obj, subresource, append([]SubResourceCreateOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *subresourceClientWithFieldOwner) Update(ctx context.Context, obj Object, opts ...SubResourceUpdateOption) error {
	return f.subresourceWriter.Update(ctx, obj, append([]SubResourceUpdateOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *subresourceClientWithFieldOwner) Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourcePatchOption) error {
	return f.subresourceWriter.Patch(ctx, obj, patch, append([]SubResourcePatchOption{FieldOwner(f.owner)}, opts...)...)
}

func (f *subresourceClientWithFieldOwner) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...SubResourceApplyOption) error {
	return f.subresourceWriter.Apply(ctx, obj, append([]SubResourceApplyOption{FieldOwner(f.owner)}, opts...)...)
}
