/*
Copyright 2023 The Kubernetes Authors.

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

package cache

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// delegatingByGVKCache delegates to a type-specific cache if present
// and uses the defaultCache otherwise.
type delegatingByGVKCache struct {
	scheme       *runtime.Scheme
	caches       map[schema.GroupVersionKind]Cache
	defaultCache Cache
}

func (dbt *delegatingByGVKCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	cache, err := dbt.cacheForObject(obj)
	if err != nil {
		return err
	}
	return cache.Get(ctx, key, obj, opts...)
}

func (dbt *delegatingByGVKCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	cache, err := dbt.cacheForObject(list)
	if err != nil {
		return err
	}
	return cache.List(ctx, list, opts...)
}

func (dbt *delegatingByGVKCache) RemoveInformer(ctx context.Context, obj client.Object) error {
	cache, err := dbt.cacheForObject(obj)
	if err != nil {
		return err
	}
	return cache.RemoveInformer(ctx, obj)
}

func (dbt *delegatingByGVKCache) GetInformer(ctx context.Context, obj client.Object, opts ...InformerGetOption) (Informer, error) {
	cache, err := dbt.cacheForObject(obj)
	if err != nil {
		return nil, err
	}
	return cache.GetInformer(ctx, obj, opts...)
}

func (dbt *delegatingByGVKCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...InformerGetOption) (Informer, error) {
	return dbt.cacheForGVK(gvk).GetInformerForKind(ctx, gvk, opts...)
}

func (dbt *delegatingByGVKCache) Start(ctx context.Context) error {
	allCaches := slices.Collect(maps.Values(dbt.caches))
	allCaches = append(allCaches, dbt.defaultCache)

	wg := &sync.WaitGroup{}
	errs := make(chan error)
	for idx := range allCaches {
		cache := allCaches[idx]
		wg.Go(func() {
			if err := cache.Start(ctx); err != nil {
				errs <- err
			}
		})
	}

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		wg.Wait()
		return nil
	}
}

func (dbt *delegatingByGVKCache) WaitForCacheSync(ctx context.Context) bool {
	synced := true
	for _, cache := range append(slices.Collect(maps.Values(dbt.caches)), dbt.defaultCache) {
		if !cache.WaitForCacheSync(ctx) {
			synced = false
		}
	}

	return synced
}

func (dbt *delegatingByGVKCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	cache, err := dbt.cacheForObject(obj)
	if err != nil {
		return err
	}
	return cache.IndexField(ctx, obj, field, extractValue)
}

func (dbt *delegatingByGVKCache) cacheForObject(o runtime.Object) (Cache, error) {
	gvk, err := apiutil.GVKForObject(o, dbt.scheme)
	if err != nil {
		return nil, err
	}
	gvk.Kind = strings.TrimSuffix(gvk.Kind, "List")
	return dbt.cacheForGVK(gvk), nil
}

func (dbt *delegatingByGVKCache) cacheForGVK(gvk schema.GroupVersionKind) Cache {
	if specific, hasSpecific := dbt.caches[gvk]; hasSpecific {
		return specific
	}

	return dbt.defaultCache
}
