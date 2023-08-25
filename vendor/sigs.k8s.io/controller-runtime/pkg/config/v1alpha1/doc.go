/*
Copyright 2020 The Kubernetes Authors.

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

// Package v1alpha1 provides the ControllerManagerConfiguration used for
// configuring ctrl.Manager
// +kubebuilder:object:generate=true
//
// Deprecated: The component config package has been deprecated and will be removed in a future release. Users should migrate to their own config implementation, please share feedback in https://github.com/kubernetes-sigs/controller-runtime/issues/895.
package v1alpha1
