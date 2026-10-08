// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// Compile-time interface assertions.
var (
	_ cache.ListerWatcher            = (*genListWatcher[k8sRuntime.Object])(nil)
	_ cache.ListerWatcherWithContext = (*genListWatcher[k8sRuntime.Object])(nil)
	_ cache.ListerWatcher            = (*listWatcherWithModifier)(nil)
	_ cache.ListerWatcherWithContext = (*listWatcherWithModifier)(nil)
)

// typedListWatcher is a generic interface that all the typed k8s clients match.
type typedListWatcher[T k8sRuntime.Object] interface {
	List(ctx context.Context, opts metav1.ListOptions) (T, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// genListWatcher takes a typed list watcher and implements cache.ListerWatcher
// and cache.ListerWatcherWithContext using it.
type genListWatcher[T k8sRuntime.Object] struct {
	lw typedListWatcher[T]
}

func (g *genListWatcher[T]) ListWithContext(ctx context.Context, opts metav1.ListOptions) (k8sRuntime.Object, error) {
	return g.lw.List(ctx, opts)
}

func (g *genListWatcher[T]) WatchWithContext(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return g.lw.Watch(ctx, opts)
}

func (g *genListWatcher[T]) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	return g.ListWithContext(context.Background(), opts)
}

func (g *genListWatcher[T]) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return g.WatchWithContext(context.Background(), opts)
}

// ListerWatcherFromTyped adapts a typed k8s client to cache.ListerWatcher so it can be used
// with an informer. With this construction we can use fake clients for testing,
// which would not be possible if we used NewListWatchFromClient and RESTClient().
func ListerWatcherFromTyped[T k8sRuntime.Object](lw typedListWatcher[T]) cache.ListerWatcher {
	return &genListWatcher[T]{lw: lw}
}

type listWatcherWithModifier struct {
	inner        cache.ListerWatcherWithContext
	optsModifier func(*metav1.ListOptions)
}

func (lw *listWatcherWithModifier) ListWithContext(ctx context.Context, opts metav1.ListOptions) (k8sRuntime.Object, error) {
	lw.optsModifier(&opts)
	return lw.inner.ListWithContext(ctx, opts)
}

func (lw *listWatcherWithModifier) WatchWithContext(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	lw.optsModifier(&opts)
	return lw.inner.WatchWithContext(ctx, opts)
}

func (lw *listWatcherWithModifier) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	return lw.ListWithContext(context.Background(), opts)
}

func (lw *listWatcherWithModifier) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return lw.WatchWithContext(context.Background(), opts)
}

func ListerWatcherWithFields(lw cache.ListerWatcher, fieldSelector fields.Selector) cache.ListerWatcher {
	return ListerWatcherWithModifier(
		lw,
		func(opts *metav1.ListOptions) { opts.FieldSelector = fieldSelector.String() })
}

func ListerWatcherWithModifier(lw cache.ListerWatcher, optsModifier func(*metav1.ListOptions)) cache.ListerWatcher {
	return &listWatcherWithModifier{
		inner:        cache.ToListerWatcherWithContext(lw),
		optsModifier: optsModifier,
	}
}

func ListerWatcherWithModifiers(lw cache.ListerWatcher, opts ...func(*metav1.ListOptions)) cache.ListerWatcher {
	for _, opt := range opts {
		lw = ListerWatcherWithModifier(lw, opt)
	}
	return lw
}
