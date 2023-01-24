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

// typedListWatcher is a generic interface that all the typed k8s clients match.
type typedListWatcher[T k8sRuntime.Object] interface {
	List(ctx context.Context, opts metav1.ListOptions) (T, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// genListWatcher takes a typed list watcher and implements cache.ListWatch
// using it.
type genListWatcher[T k8sRuntime.Object] struct {
	lw typedListWatcher[T]
}

func (g *genListWatcher[T]) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	return g.lw.List(context.Background(), opts)
}

func (g *genListWatcher[T]) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return g.lw.Watch(context.Background(), opts)
}

// ListerWatcherFromTyped adapts a typed k8s client to cache.ListerWatcher so it can be used
// with an informer. With this construction we can use fake clients for testing,
// which would not be possible if we used NewListWatchFromClient and RESTClient().
func ListerWatcherFromTyped[T k8sRuntime.Object](lw typedListWatcher[T]) cache.ListerWatcher {
	return &genListWatcher[T]{lw: lw}
}

type listWatcherWithModifier struct {
	inner        cache.ListerWatcher
	optsModifier func(*metav1.ListOptions)
}

func (lw *listWatcherWithModifier) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	lw.optsModifier(&opts)
	return lw.inner.List(opts)
}

func (lw *listWatcherWithModifier) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	lw.optsModifier(&opts)
	return lw.inner.Watch(opts)
}

func ListerWatcherWithFields(lw cache.ListerWatcher, fieldSelector fields.Selector) cache.ListerWatcher {
	return ListerWatcherWithModifier(
		lw,
		func(opts *metav1.ListOptions) { opts.FieldSelector = fieldSelector.String() })
}

func ListerWatcherWithModifier(lw cache.ListerWatcher, optsModifier func(*metav1.ListOptions)) cache.ListerWatcher {
	return &listWatcherWithModifier{
		inner:        lw,
		optsModifier: optsModifier,
	}
}
