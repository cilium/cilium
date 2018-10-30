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

type Annotator interface {
	// AnnotatePod annotates the pod k8sPodName in namespace k8sNamespace with
	// the annotation annotationKey=annotationValue. Returns an error if
	// annotating failed.
	AnnotatePod(k8sNamespace, k8sPodName, annotationKey, annotationValue string) error
}

type DummyAnnotator struct {
}

func (d DummyAnnotator) AnnotatePod(k8sNamespace, k8sPodName, annotationKey, annotationValue string) error {
	return nil
}
