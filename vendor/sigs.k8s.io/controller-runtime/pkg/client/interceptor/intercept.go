package interceptor

import (
	"context"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Funcs contains functions that are called instead of the underlying client's methods.
type Funcs struct {
	Get               func(ctx context.Context, client client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
	List              func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error
	Create            func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error
	Delete            func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.DeleteOption) error
	DeleteAllOf       func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error
	Update            func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error
	Patch             func(ctx context.Context, client client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error
	Apply             func(ctx context.Context, client client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error
	Watch             func(ctx context.Context, client client.WithWatch, obj client.ObjectList, opts ...client.ListOption) (watch.Interface, error)
	SubResource       func(client client.WithWatch, subResource string) client.SubResourceClient
	SubResourceGet    func(ctx context.Context, client client.Client, subResourceName string, obj client.Object, subResource client.Object, opts ...client.SubResourceGetOption) error
	SubResourceCreate func(ctx context.Context, client client.Client, subResourceName string, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error
	SubResourceUpdate func(ctx context.Context, client client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error
	SubResourcePatch  func(ctx context.Context, client client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error
}

// NewClient returns a new interceptor client that calls the functions in funcs instead of the underlying client's methods, if they are not nil.
func NewClient(interceptedClient client.WithWatch, funcs Funcs) client.WithWatch {
	return interceptor{
		client: interceptedClient,
		funcs:  funcs,
	}
}

type interceptor struct {
	client client.WithWatch
	funcs  Funcs
}

var _ client.WithWatch = &interceptor{}

func (c interceptor) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return c.client.GroupVersionKindFor(obj)
}

func (c interceptor) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return c.client.IsObjectNamespaced(obj)
}

func (c interceptor) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.funcs.Get != nil {
		return c.funcs.Get(ctx, c.client, key, obj, opts...)
	}
	return c.client.Get(ctx, key, obj, opts...)
}

func (c interceptor) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.funcs.List != nil {
		return c.funcs.List(ctx, c.client, list, opts...)
	}
	return c.client.List(ctx, list, opts...)
}

func (c interceptor) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.funcs.Create != nil {
		return c.funcs.Create(ctx, c.client, obj, opts...)
	}
	return c.client.Create(ctx, obj, opts...)
}

func (c interceptor) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if c.funcs.Delete != nil {
		return c.funcs.Delete(ctx, c.client, obj, opts...)
	}
	return c.client.Delete(ctx, obj, opts...)
}

func (c interceptor) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.funcs.Update != nil {
		return c.funcs.Update(ctx, c.client, obj, opts...)
	}
	return c.client.Update(ctx, obj, opts...)
}

func (c interceptor) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if c.funcs.Patch != nil {
		return c.funcs.Patch(ctx, c.client, obj, patch, opts...)
	}
	return c.client.Patch(ctx, obj, patch, opts...)
}

func (c interceptor) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	if c.funcs.Apply != nil {
		return c.funcs.Apply(ctx, c.client, obj, opts...)
	}

	return c.client.Apply(ctx, obj, opts...)
}

func (c interceptor) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	if c.funcs.DeleteAllOf != nil {
		return c.funcs.DeleteAllOf(ctx, c.client, obj, opts...)
	}
	return c.client.DeleteAllOf(ctx, obj, opts...)
}

func (c interceptor) Status() client.SubResourceWriter {
	return c.SubResource("status")
}

func (c interceptor) SubResource(subResource string) client.SubResourceClient {
	if c.funcs.SubResource != nil {
		return c.funcs.SubResource(c.client, subResource)
	}
	return subResourceInterceptor{
		subResourceName: subResource,
		client:          c.client,
		funcs:           c.funcs,
	}
}

func (c interceptor) Scheme() *runtime.Scheme {
	return c.client.Scheme()
}

func (c interceptor) RESTMapper() meta.RESTMapper {
	return c.client.RESTMapper()
}

func (c interceptor) Watch(ctx context.Context, obj client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
	if c.funcs.Watch != nil {
		return c.funcs.Watch(ctx, c.client, obj, opts...)
	}
	return c.client.Watch(ctx, obj, opts...)
}

type subResourceInterceptor struct {
	subResourceName string
	client          client.Client
	funcs           Funcs
}

var _ client.SubResourceClient = &subResourceInterceptor{}

func (s subResourceInterceptor) Get(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceGetOption) error {
	if s.funcs.SubResourceGet != nil {
		return s.funcs.SubResourceGet(ctx, s.client, s.subResourceName, obj, subResource, opts...)
	}
	return s.client.SubResource(s.subResourceName).Get(ctx, obj, subResource, opts...)
}

func (s subResourceInterceptor) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	if s.funcs.SubResourceCreate != nil {
		return s.funcs.SubResourceCreate(ctx, s.client, s.subResourceName, obj, subResource, opts...)
	}
	return s.client.SubResource(s.subResourceName).Create(ctx, obj, subResource, opts...)
}

func (s subResourceInterceptor) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if s.funcs.SubResourceUpdate != nil {
		return s.funcs.SubResourceUpdate(ctx, s.client, s.subResourceName, obj, opts...)
	}
	return s.client.SubResource(s.subResourceName).Update(ctx, obj, opts...)
}

func (s subResourceInterceptor) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if s.funcs.SubResourcePatch != nil {
		return s.funcs.SubResourcePatch(ctx, s.client, s.subResourceName, obj, patch, opts...)
	}
	return s.client.SubResource(s.subResourceName).Patch(ctx, obj, patch, opts...)
}
