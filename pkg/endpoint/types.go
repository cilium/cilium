// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	"github.com/cilium/cilium/pkg/labels"
)

// Metadata is the collection of endpoint information used for Cilium
// endpoint creation and management.
type Metadata struct {
	Pod            *slim_corev1.Pod
	ContainerPorts []slim_corev1.ContainerPort
	IdentityLabels labels.Labels
	InfoLabels     labels.Labels
	Annotations    map[string]string
}
