/*
Copyright 2020 The Kubernetes Authors.

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
)

// NewDryRunClient wraps an existing client and enforces DryRun mode
// on all mutating api calls.
func NewDryRunClient(c Client) Client {
	return &dryRunClient{client: c}
}

var _ Client = &dryRunClient{}

// dryRunClient is a Client that wraps another Client in order to enforce DryRun mode.
type dryRunClient struct {
	client Client
}

// Scheme returns the scheme this client is using.
func (c *dryRunClient) Scheme() *runtime.Scheme {
	return c.client.Scheme()
}

// RESTMapper returns the rest mapper this client is using.
func (c *dryRunClient) RESTMapper() meta.RESTMapper {
	return c.client.RESTMapper()
}

// Create implements client.Client.
func (c *dryRunClient) Create(ctx context.Context, obj Object, opts ...CreateOption) error {
	return c.client.Create(ctx, obj, append(opts, DryRunAll)...)
}

// Update implements client.Client.
func (c *dryRunClient) Update(ctx context.Context, obj Object, opts ...UpdateOption) error {
	return c.client.Update(ctx, obj, append(opts, DryRunAll)...)
}

// Delete implements client.Client.
func (c *dryRunClient) Delete(ctx context.Context, obj Object, opts ...DeleteOption) error {
	return c.client.Delete(ctx, obj, append(opts, DryRunAll)...)
}

// DeleteAllOf implements client.Client.
func (c *dryRunClient) DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error {
	return c.client.DeleteAllOf(ctx, obj, append(opts, DryRunAll)...)
}

// Patch implements client.Client.
func (c *dryRunClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error {
	return c.client.Patch(ctx, obj, patch, append(opts, DryRunAll)...)
}

// Get implements client.Client.
func (c *dryRunClient) Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) error {
	return c.client.Get(ctx, key, obj, opts...)
}

// List implements client.Client.
func (c *dryRunClient) List(ctx context.Context, obj ObjectList, opts ...ListOption) error {
	return c.client.List(ctx, obj, opts...)
}

// Status implements client.StatusClient.
func (c *dryRunClient) Status() SubResourceWriter {
	return c.SubResource("status")
}

// SubResource implements client.SubResourceClient.
func (c *dryRunClient) SubResource(subResource string) SubResourceClient {
	return &dryRunSubResourceClient{client: c.client.SubResource(subResource)}
}

// ensure dryRunSubResourceWriter implements client.SubResourceWriter.
var _ SubResourceWriter = &dryRunSubResourceClient{}

// dryRunSubResourceClient is client.SubResourceWriter that writes status subresource with dryRun mode
// enforced.
type dryRunSubResourceClient struct {
	client SubResourceClient
}

func (sw *dryRunSubResourceClient) Get(ctx context.Context, obj, subResource Object, opts ...SubResourceGetOption) error {
	return sw.client.Get(ctx, obj, subResource, opts...)
}

func (sw *dryRunSubResourceClient) Create(ctx context.Context, obj, subResource Object, opts ...SubResourceCreateOption) error {
	return sw.client.Create(ctx, obj, subResource, append(opts, DryRunAll)...)
}

// Update implements client.SubResourceWriter.
func (sw *dryRunSubResourceClient) Update(ctx context.Context, obj Object, opts ...SubResourceUpdateOption) error {
	return sw.client.Update(ctx, obj, append(opts, DryRunAll)...)
}

// Patch implements client.SubResourceWriter.
func (sw *dryRunSubResourceClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourcePatchOption) error {
	return sw.client.Patch(ctx, obj, patch, append(opts, DryRunAll)...)
}
