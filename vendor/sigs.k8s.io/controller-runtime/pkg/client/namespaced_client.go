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
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// NewNamespacedClient wraps an existing client enforcing the namespace value.
// All functions using this client will have the same namespace declared here.
func NewNamespacedClient(c Client, ns string) Client {
	return &namespacedClient{
		client:    c,
		namespace: ns,
	}
}

var _ Client = &namespacedClient{}

// namespacedClient is a Client that wraps another Client in order to enforce the specified namespace value.
type namespacedClient struct {
	namespace string
	client    Client
}

// Scheme returns the scheme this client is using.
func (n *namespacedClient) Scheme() *runtime.Scheme {
	return n.client.Scheme()
}

// RESTMapper returns the scheme this client is using.
func (n *namespacedClient) RESTMapper() meta.RESTMapper {
	return n.client.RESTMapper()
}

// GroupVersionKindFor returns the GroupVersionKind for the given object.
func (n *namespacedClient) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return n.client.GroupVersionKindFor(obj)
}

// IsObjectNamespaced returns true if the GroupVersionKind of the object is namespaced.
func (n *namespacedClient) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return n.client.IsObjectNamespaced(obj)
}

// Create implements client.Client.
func (n *namespacedClient) Create(ctx context.Context, obj Object, opts ...CreateOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != n.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), n.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(n.namespace)
	}
	return n.client.Create(ctx, obj, opts...)
}

// Update implements client.Client.
func (n *namespacedClient) Update(ctx context.Context, obj Object, opts ...UpdateOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != n.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), n.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(n.namespace)
	}
	return n.client.Update(ctx, obj, opts...)
}

// Delete implements client.Client.
func (n *namespacedClient) Delete(ctx context.Context, obj Object, opts ...DeleteOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != n.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), n.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(n.namespace)
	}
	return n.client.Delete(ctx, obj, opts...)
}

// DeleteAllOf implements client.Client.
func (n *namespacedClient) DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	if isNamespaceScoped {
		opts = append(opts, InNamespace(n.namespace))
	}
	return n.client.DeleteAllOf(ctx, obj, opts...)
}

// Patch implements client.Client.
func (n *namespacedClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != n.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), n.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(n.namespace)
	}
	return n.client.Patch(ctx, obj, patch, opts...)
}

func (n *namespacedClient) setNamespaceForApplyConfigIfNamespaceScoped(obj runtime.ApplyConfiguration) error {
	var gvk schema.GroupVersionKind
	switch o := obj.(type) {
	case applyConfiguration:
		var err error
		gvk, err = gvkFromApplyConfiguration(o)
		if err != nil {
			return err
		}
	case *unstructuredApplyConfiguration:
		gvk = o.GroupVersionKind()
	default:
		return fmt.Errorf("object %T is not a valid apply configuration", obj)
	}
	isNamespaceScoped, err := apiutil.IsGVKNamespaced(gvk, n.RESTMapper())
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}
	if isNamespaceScoped {
		switch o := obj.(type) {
		case applyConfiguration:
			if o.GetNamespace() != nil && *o.GetNamespace() != "" && *o.GetNamespace() != n.namespace {
				return fmt.Errorf("namespace %s provided for the object %s does not match the namespace %s on the client",
					*o.GetNamespace(), ptr.Deref(o.GetName(), ""), n.namespace)
			}
			v := reflect.ValueOf(o)
			withNamespace := v.MethodByName("WithNamespace")
			if !withNamespace.IsValid() {
				return fmt.Errorf("ApplyConfiguration %T does not have a WithNamespace method", o)
			}
			if tp := withNamespace.Type(); tp.NumIn() != 1 || tp.In(0).Kind() != reflect.String {
				return fmt.Errorf("WithNamespace method of ApplyConfiguration %T must take a single string argument", o)
			}
			withNamespace.Call([]reflect.Value{reflect.ValueOf(n.namespace)})
		case *unstructuredApplyConfiguration:
			if o.GetNamespace() != "" && o.GetNamespace() != n.namespace {
				return fmt.Errorf("namespace %s provided for the object %s does not match the namespace %s on the client",
					o.GetNamespace(), o.GetName(), n.namespace)
			}
			o.SetNamespace(n.namespace)
		}
	}

	return nil
}

func (n *namespacedClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...ApplyOption) error {
	if err := n.setNamespaceForApplyConfigIfNamespaceScoped(obj); err != nil {
		return err
	}

	return n.client.Apply(ctx, obj, opts...)
}

// Get implements client.Client.
func (n *namespacedClient) Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}
	if isNamespaceScoped {
		if key.Namespace != "" && key.Namespace != n.namespace {
			return fmt.Errorf("namespace %s provided for the object %s does not match the namespace %s on the client", key.Namespace, obj.GetName(), n.namespace)
		}
		key.Namespace = n.namespace
	}
	return n.client.Get(ctx, key, obj, opts...)
}

// List implements client.Client.
func (n *namespacedClient) List(ctx context.Context, obj ObjectList, opts ...ListOption) error {
	isNamespaceScoped, err := n.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	if isNamespaceScoped && n.namespace != "" {
		opts = append(opts, InNamespace(n.namespace))
	}
	return n.client.List(ctx, obj, opts...)
}

// Status implements client.StatusClient.
func (n *namespacedClient) Status() SubResourceWriter {
	return n.SubResource("status")
}

// SubResource implements client.SubResourceClient.
func (n *namespacedClient) SubResource(subResource string) SubResourceClient {
	return &namespacedClientSubResourceClient{
		client:           n.client.SubResource(subResource),
		namespacedclient: n,
	}
}

// ensure namespacedClientSubResourceClient implements client.SubResourceClient.
var _ SubResourceClient = &namespacedClientSubResourceClient{}

type namespacedClientSubResourceClient struct {
	client           SubResourceClient
	namespacedclient *namespacedClient
}

func (nsw *namespacedClientSubResourceClient) Get(ctx context.Context, obj, subResource Object, opts ...SubResourceGetOption) error {
	isNamespaceScoped, err := nsw.namespacedclient.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != nsw.namespacedclient.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), nsw.namespacedclient.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(nsw.namespacedclient.namespace)
	}

	return nsw.client.Get(ctx, obj, subResource, opts...)
}

func (nsw *namespacedClientSubResourceClient) Create(ctx context.Context, obj, subResource Object, opts ...SubResourceCreateOption) error {
	isNamespaceScoped, err := nsw.namespacedclient.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != nsw.namespacedclient.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), nsw.namespacedclient.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(nsw.namespacedclient.namespace)
	}

	return nsw.client.Create(ctx, obj, subResource, opts...)
}

// Update implements client.SubResourceWriter.
func (nsw *namespacedClientSubResourceClient) Update(ctx context.Context, obj Object, opts ...SubResourceUpdateOption) error {
	isNamespaceScoped, err := nsw.namespacedclient.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != nsw.namespacedclient.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), nsw.namespacedclient.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(nsw.namespacedclient.namespace)
	}
	return nsw.client.Update(ctx, obj, opts...)
}

// Patch implements client.SubResourceWriter.
func (nsw *namespacedClientSubResourceClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourcePatchOption) error {
	isNamespaceScoped, err := nsw.namespacedclient.IsObjectNamespaced(obj)
	if err != nil {
		return fmt.Errorf("error finding the scope of the object: %w", err)
	}

	objectNamespace := obj.GetNamespace()
	if objectNamespace != nsw.namespacedclient.namespace && objectNamespace != "" {
		return fmt.Errorf("namespace %s of the object %s does not match the namespace %s on the client", objectNamespace, obj.GetName(), nsw.namespacedclient.namespace)
	}

	if isNamespaceScoped && objectNamespace == "" {
		obj.SetNamespace(nsw.namespacedclient.namespace)
	}
	return nsw.client.Patch(ctx, obj, patch, opts...)
}

func (nsw *namespacedClientSubResourceClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...SubResourceApplyOption) error {
	if err := nsw.namespacedclient.setNamespaceForApplyConfigIfNamespaceScoped(obj); err != nil {
		return err
	}
	return nsw.client.Apply(ctx, obj, opts...)
}
