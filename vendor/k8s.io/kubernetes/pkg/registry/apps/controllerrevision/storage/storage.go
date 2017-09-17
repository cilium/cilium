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
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/registry/apps/controllerrevision"
	"k8s.io/kubernetes/pkg/registry/cachesize"
)

// REST implements a RESTStorage for ControllerRevision
type REST struct {
	*genericregistry.Store
}

// NewREST returns a RESTStorage object that will work with ControllerRevision objects.
func NewREST(optsGetter generic.RESTOptionsGetter) *REST {
	store := &genericregistry.Store{
		Copier:                   api.Scheme,
		NewFunc:                  func() runtime.Object { return &apps.ControllerRevision{} },
		NewListFunc:              func() runtime.Object { return &apps.ControllerRevisionList{} },
		DefaultQualifiedResource: apps.Resource("controllerrevisions"),
		WatchCacheSize:           cachesize.GetWatchCacheSizeByResource("controllerrevisions"),

		CreateStrategy: controllerrevision.Strategy,
		UpdateStrategy: controllerrevision.Strategy,
		DeleteStrategy: controllerrevision.Strategy,
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter}
	if err := store.CompleteWithOptions(options); err != nil {
		panic(err)
	}
	return &REST{store}
}
