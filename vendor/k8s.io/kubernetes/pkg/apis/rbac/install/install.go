/*
Copyright 2016 The Kubernetes Authors.

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

// Package install installs the batch API group, making it available as
// an option to all of the API encoding/decoding machinery.
package install

import (
	"k8s.io/apimachinery/pkg/apimachinery/announced"
	"k8s.io/apimachinery/pkg/apimachinery/registered"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/apis/rbac/v1"
	"k8s.io/kubernetes/pkg/apis/rbac/v1alpha1"
	"k8s.io/kubernetes/pkg/apis/rbac/v1beta1"
)

func init() {
	Install(api.GroupFactoryRegistry, api.Registry, api.Scheme)
}

// Install registers the API group and adds types to a scheme
func Install(groupFactoryRegistry announced.APIGroupFactoryRegistry, registry *registered.APIRegistrationManager, scheme *runtime.Scheme) {
	if err := announced.NewGroupMetaFactory(
		&announced.GroupMetaFactoryArgs{
			GroupName: rbac.GroupName,
			// Rollout plan:
			// 1.8:
			// * announce deprecation of v1alpha1 (people should use v1beta1 or v1)
			// 1.9 (once all version-skewed API servers in an HA cluster are capable of reading/writing v1 to etcd):
			// * move v1 to the beginning
			// * add RBAC objects to update-storage-objects.sh
			// * update TestEtcdStoragePath to expect objects to be stored in v1
			// * document that RBAC storage objects should be migrated to ensure storage is a v1-level (via update-storage-objects.sh or otherwise)
			// 1.10 (once all stored objects are at v1):
			// * remove v1alpha1
			VersionPreferenceOrder:     []string{v1beta1.SchemeGroupVersion.Version, v1.SchemeGroupVersion.Version, v1alpha1.SchemeGroupVersion.Version},
			RootScopedKinds:            sets.NewString("ClusterRole", "ClusterRoleBinding"),
			AddInternalObjectsToScheme: rbac.AddToScheme,
		},
		announced.VersionToSchemeFunc{
			v1.SchemeGroupVersion.Version:       v1.AddToScheme,
			v1beta1.SchemeGroupVersion.Version:  v1beta1.AddToScheme,
			v1alpha1.SchemeGroupVersion.Version: v1alpha1.AddToScheme,
		},
	).Announce(groupFactoryRegistry).RegisterAndEnable(registry, scheme); err != nil {
		panic(err)
	}
}
