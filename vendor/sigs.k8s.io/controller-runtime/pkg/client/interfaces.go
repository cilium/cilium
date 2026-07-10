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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

// ObjectKey identifies a Kubernetes Object.
type ObjectKey = types.NamespacedName

// ObjectKeyFromObject returns the ObjectKey given a runtime.Object.
func ObjectKeyFromObject(obj Object) ObjectKey {
	return ObjectKey{Namespace: obj.GetNamespace(), Name: obj.GetName()}
}

// Patch is a patch that can be applied to a Kubernetes object.
type Patch interface {
	// Type is the PatchType of the patch.
	Type() types.PatchType
	// Data is the raw data representing the patch.
	Data(obj Object) ([]byte, error)
}

// TODO(directxman12): is there a sane way to deal with get/delete options?

// Reader knows how to read and list Kubernetes objects.
type Reader interface {
	// Get retrieves an obj for the given object key from the Kubernetes Cluster.
	// obj must be a struct pointer so that obj can be updated with the response
	// returned by the Server.
	Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) error

	// List retrieves list of objects for a given namespace and list options. On a
	// successful call, Items field in the list will be populated with the
	// result returned from the server.
	List(ctx context.Context, list ObjectList, opts ...ListOption) error
}

// Writer knows how to create, delete, and update Kubernetes objects.
type Writer interface {
	// Apply applies the given apply configuration to the Kubernetes cluster.
	Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...ApplyOption) error

	// Create saves the object obj in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Create(ctx context.Context, obj Object, opts ...CreateOption) error

	// Delete deletes the given obj from Kubernetes cluster.
	Delete(ctx context.Context, obj Object, opts ...DeleteOption) error

	// Update updates the given obj in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Update(ctx context.Context, obj Object, opts ...UpdateOption) error

	// Patch patches the given obj in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error

	// DeleteAllOf deletes all objects of the given type matching the given options.
	DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error
}

// StatusClient knows how to create a client which can update status subresource
// for kubernetes objects.
type StatusClient interface {
	Status() SubResourceWriter
}

// SubResourceClientConstructor knows how to create a client which can update subresource
// for kubernetes objects.
type SubResourceClientConstructor interface {
	// SubResourceClientConstructor returns a subresource client for the named subResource. Known
	// upstream subResources usages are:
	// - ServiceAccount token creation:
	//     sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar"}}
	//     token := &authenticationv1.TokenRequest{}
	//     c.SubResource("token").Create(ctx, sa, token)
	//
	// - Pod eviction creation:
	//     pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar"}}
	//     c.SubResource("eviction").Create(ctx, pod, &policyv1.Eviction{})
	//
	// - Pod binding creation:
	//     pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar"}}
	//     binding := &corev1.Binding{Target: corev1.ObjectReference{Name: "my-node"}}
	//     c.SubResource("binding").Create(ctx, pod, binding)
	//
	// - CertificateSigningRequest approval:
	//     csr := &certificatesv1.CertificateSigningRequest{
	//	     ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar"},
	//       Status: certificatesv1.CertificateSigningRequestStatus{
	//         Conditions: []certificatesv1.[]CertificateSigningRequestCondition{{
	//           Type: certificatesv1.CertificateApproved,
	//           Status: corev1.ConditionTrue,
	//         }},
	//       },
	//     }
	//     c.SubResource("approval").Update(ctx, csr)
	//
	// - Scale retrieval:
	//     dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar"}}
	//     scale := &autoscalingv1.Scale{}
	//     c.SubResource("scale").Get(ctx, dep, scale)
	//
	// - Scale update:
	//     dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "bar"}}
	//     scale := &autoscalingv1.Scale{Spec: autoscalingv1.ScaleSpec{Replicas: 2}}
	//     c.SubResource("scale").Update(ctx, dep, client.WithSubResourceBody(scale))
	SubResource(subResource string) SubResourceClient
}

// StatusWriter is kept for backward compatibility.
type StatusWriter = SubResourceWriter

// SubResourceReader knows how to read SubResources
type SubResourceReader interface {
	Get(ctx context.Context, obj Object, subResource Object, opts ...SubResourceGetOption) error
}

// SubResourceWriter knows how to update subresource of a Kubernetes object.
type SubResourceWriter interface {
	// Create saves the subResource object in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Create(ctx context.Context, obj Object, subResource Object, opts ...SubResourceCreateOption) error

	// Update updates the fields corresponding to the status subresource for the
	// given obj. obj must be a struct pointer so that obj can be updated
	// with the content returned by the Server.
	Update(ctx context.Context, obj Object, opts ...SubResourceUpdateOption) error

	// Patch patches the given object's subresource. obj must be a struct
	// pointer so that obj can be updated with the content returned by the
	// Server.
	Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourcePatchOption) error

	// Apply applies the given apply configurations subresource.
	Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...SubResourceApplyOption) error
}

// SubResourceClient knows how to perform CRU operations on Kubernetes objects.
type SubResourceClient interface {
	SubResourceReader
	SubResourceWriter
}

// Client knows how to perform CRUD operations on Kubernetes objects.
type Client interface {
	Reader
	Writer
	StatusClient
	SubResourceClientConstructor

	// Scheme returns the scheme this client is using.
	Scheme() *runtime.Scheme
	// RESTMapper returns the rest this client is using.
	RESTMapper() meta.RESTMapper
	// GroupVersionKindFor returns the GroupVersionKind for the given object.
	GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error)
	// IsObjectNamespaced returns true if the GroupVersionKind of the object is namespaced.
	IsObjectNamespaced(obj runtime.Object) (bool, error)
}

// WithWatch supports Watch on top of the CRUD operations supported by
// the normal Client. Its intended use-case are CLI apps that need to wait for
// events.
type WithWatch interface {
	Client
	Watch(ctx context.Context, obj ObjectList, opts ...ListOption) (watch.Interface, error)
}

// IndexerFunc knows how to take an object and turn it into a series
// of non-namespaced keys. Namespaced objects are automatically given
// namespaced and non-spaced variants, so keys do not need to include namespace.
type IndexerFunc func(Object) []string

// FieldIndexer knows how to index over a particular "field" such that it
// can later be used by a field selector.
type FieldIndexer interface {
	// IndexField adds an index with the given field name on the given object type
	// by using the given function to extract the value for that field.  If you want
	// compatibility with the Kubernetes API server, only return one key, and only use
	// fields that the API server supports.  Otherwise, you can return multiple keys,
	// and "equality" in the field selector means that at least one key matches the value.
	// The FieldIndexer will automatically take care of indexing over namespace
	// and supporting efficient all-namespace queries.
	IndexField(ctx context.Context, obj Object, field string, extractValue IndexerFunc) error
}

// IgnoreNotFound returns nil on NotFound errors.
// All other values that are not NotFound errors or nil are returned unmodified.
func IgnoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// IgnoreAlreadyExists returns nil on AlreadyExists errors.
// All other values that are not AlreadyExists errors or nil are returned unmodified.
func IgnoreAlreadyExists(err error) error {
	if apierrors.IsAlreadyExists(err) {
		return nil
	}

	return err
}
