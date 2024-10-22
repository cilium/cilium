/*
Copyright 2024 The Kubernetes Authors.

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

package v1

import "k8s.io/apimachinery/pkg/runtime/schema"

const (
	// Group is the API group for the Conformance Report API.
	Group = "gateway.networking.k8s.io"

	// Version is the API version for the Conformance Report API.
	Version = "v1"
)

// GroupVersion is the API group and version for the Conformance Report API.
var GroupVersion = schema.GroupVersion{Group: Group, Version: Version}
