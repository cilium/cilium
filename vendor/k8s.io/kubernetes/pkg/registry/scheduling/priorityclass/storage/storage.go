/*
Copyright 2017 The Kubernetes Authors.

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

package storage

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/api"
	schedulingapi "k8s.io/kubernetes/pkg/apis/scheduling"
	"k8s.io/kubernetes/pkg/registry/cachesize"
	"k8s.io/kubernetes/pkg/registry/scheduling/priorityclass"
)

// rest implements a RESTStorage for priority classes against etcd
type REST struct {
	*genericregistry.Store
}

// NewREST returns a RESTStorage object that will work against priority classes.
func NewREST(optsGetter generic.RESTOptionsGetter) *REST {
	store := &genericregistry.Store{
		Copier:                   api.Scheme,
		NewFunc:                  func() runtime.Object { return &schedulingapi.PriorityClass{} },
		NewListFunc:              func() runtime.Object { return &schedulingapi.PriorityClassList{} },
		DefaultQualifiedResource: schedulingapi.Resource("priorityclasses"),
		WatchCacheSize:           cachesize.GetWatchCacheSizeByResource("priorityclasses"),

		CreateStrategy: priorityclass.Strategy,
		UpdateStrategy: priorityclass.Strategy,
		DeleteStrategy: priorityclass.Strategy,
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter}
	if err := store.CompleteWithOptions(options); err != nil {
		panic(err) // TODO: Propagate error up
	}

	return &REST{store}
}

// Implement ShortNamesProvider
var _ rest.ShortNamesProvider = &REST{}

// ShortNames implements the ShortNamesProvider interface. Returns a list of short names for a resource.
func (r *REST) ShortNames() []string {
	return []string{"pc"}
}
