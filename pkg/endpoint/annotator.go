// Copyright 2018 Authors of Cilium
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

var (
	// EpAnnotator is a shared annotator amongst all endpoints. It is used to
	// annotate resources in orchestration systems with information about
	// their corresponding endpoints.
	EpAnnotator Annotator
)

// Annotator is an interface which annotates a pod. Its primary use is to
// remove pulling in Kubernetes dependencies into packages which need to
// update K8s objects with annotations.
type Annotator interface {
	// AnnotatePod annotates the pod k8sPodName in namespace k8sNamespace with
	// the annotation annotationKey=annotationValue. Returns an error if
	// annotating failed.
	AnnotatePod(k8sNamespace, k8sPodName, annotationKey, annotationValue string) error
}
