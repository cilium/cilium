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

package rest

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// FillObjectMetaSystemFields populates fields that are managed by the system on ObjectMeta.
func FillObjectMetaSystemFields(ctx genericapirequest.Context, meta metav1.Object) {
	meta.SetCreationTimestamp(metav1.Now())
	// allows admission controllers to assign a UID earlier in the request processing
	// to support tracking resources pending creation.
	uid, found := genericapirequest.UIDFrom(ctx)
	if !found {
		uid = uuid.NewUUID()
	}
	meta.SetUID(uid)
	meta.SetSelfLink("")
}

// ValidNamespace returns false if the namespace on the context differs from
// the resource.  If the resource has no namespace, it is set to the value in
// the context.
//
// TODO(sttts): move into pkg/genericapiserver/endpoints
func ValidNamespace(ctx genericapirequest.Context, resource metav1.Object) bool {
	ns, ok := genericapirequest.NamespaceFrom(ctx)
	if len(resource.GetNamespace()) == 0 {
		resource.SetNamespace(ns)
	}
	return ns == resource.GetNamespace() && ok
}
