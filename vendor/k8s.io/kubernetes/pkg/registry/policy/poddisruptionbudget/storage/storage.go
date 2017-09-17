/*
Copyright 2015 The Kubernetes Authors.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/api"
	policyapi "k8s.io/kubernetes/pkg/apis/policy"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"
	"k8s.io/kubernetes/pkg/registry/cachesize"
	"k8s.io/kubernetes/pkg/registry/policy/poddisruptionbudget"
)

// rest implements a RESTStorage for pod disruption budgets against etcd
type REST struct {
	*genericregistry.Store
}

// NewREST returns a RESTStorage object that will work against pod disruption budgets.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST) {
	store := &genericregistry.Store{
		Copier:                   api.Scheme,
		NewFunc:                  func() runtime.Object { return &policyapi.PodDisruptionBudget{} },
		NewListFunc:              func() runtime.Object { return &policyapi.PodDisruptionBudgetList{} },
		DefaultQualifiedResource: policyapi.Resource("poddisruptionbudgets"),
		WatchCacheSize:           cachesize.GetWatchCacheSizeByResource("poddisruptionbudgets"),

		CreateStrategy: poddisruptionbudget.Strategy,
		UpdateStrategy: poddisruptionbudget.Strategy,
		DeleteStrategy: poddisruptionbudget.Strategy,

		TableConvertor: printerstorage.TableConvertor{TablePrinter: printers.NewTablePrinter().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter}
	if err := store.CompleteWithOptions(options); err != nil {
		panic(err) // TODO: Propagate error up
	}

	statusStore := *store
	statusStore.UpdateStrategy = poddisruptionbudget.StatusStrategy
	return &REST{store}, &StatusREST{store: &statusStore}
}

// ShortNames implements the ShortNamesProvider interface. Returns a list of short names for a resource.
func (r *REST) ShortNames() []string {
	return []string{"pdb"}
}

// StatusREST implements the REST endpoint for changing the status of an podDisruptionBudget
type StatusREST struct {
	store *genericregistry.Store
}

func (r *StatusREST) New() runtime.Object {
	return &policyapi.PodDisruptionBudget{}
}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *StatusREST) Get(ctx genericapirequest.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx genericapirequest.Context, name string, objInfo rest.UpdatedObjectInfo) (runtime.Object, bool, error) {
	return r.store.Update(ctx, name, objInfo)
}
