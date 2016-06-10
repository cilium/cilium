/*
Copyright 2016 The Kubernetes Authors All rights reserved.

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

package v1alpha1

import (
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch/versioned"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = unversioned.GroupVersion{Group: rbac.GroupName, Version: "v1alpha1"}

func AddToScheme(scheme *runtime.Scheme) {
	addKnownTypes(scheme)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Role{},
		&RoleBinding{},
		&RoleBindingList{},
		&RoleList{},

		&ClusterRole{},
		&ClusterRoleBinding{},
		&ClusterRoleBindingList{},
		&ClusterRoleList{},
	)
	versioned.AddToGroupVersion(scheme, SchemeGroupVersion)
}

func (obj *ClusterRole) GetObjectKind() unversioned.ObjectKind            { return &obj.TypeMeta }
func (obj *ClusterRoleBinding) GetObjectKind() unversioned.ObjectKind     { return &obj.TypeMeta }
func (obj *ClusterRoleBindingList) GetObjectKind() unversioned.ObjectKind { return &obj.TypeMeta }
func (obj *ClusterRoleList) GetObjectKind() unversioned.ObjectKind        { return &obj.TypeMeta }

func (obj *Role) GetObjectKind() unversioned.ObjectKind            { return &obj.TypeMeta }
func (obj *RoleBinding) GetObjectKind() unversioned.ObjectKind     { return &obj.TypeMeta }
func (obj *RoleBindingList) GetObjectKind() unversioned.ObjectKind { return &obj.TypeMeta }
func (obj *RoleList) GetObjectKind() unversioned.ObjectKind        { return &obj.TypeMeta }
