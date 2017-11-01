// Copyright 2017 Authors of Cilium
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

package k8s

import (
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// DeepCopyv1beta1Ingress returns a DeepCopy of the given ingress.
// Deprecated
func DeepCopyv1beta1Ingress(ing *v1beta1.Ingress) *v1beta1.Ingress {
	// FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
	return ing
}
