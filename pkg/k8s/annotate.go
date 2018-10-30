// Copyright 2016-2018 Authors of Cilium
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
	"fmt"
	"k8s.io/client-go/kubernetes"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// K8sClient implements the endpoint.Annotator interface. It does not contain
// any fields, as it uses the client variable that is scoped to this package.
type K8sClient struct {
}

// GetClient returns the client variable scoped to this package.
func (k8sCli *K8sClient) GetClient() kubernetes.Interface {
	return client
}

// AnnotatePod adds a Kubernetes annotation with key annotationKey and value
// annotationValue
func (k8sCli K8sClient) AnnotatePod(k8sNamespace, k8sPodName, annotationKey, annotationValue string) error {

	pod, err := k8sCli.GetClient().CoreV1().Pods(k8sNamespace).Get(k8sPodName, meta_v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to annotate pod, cannot retrieve pod: %s", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations[annotationKey] = annotationValue
	pod, err = Client().CoreV1().Pods(k8sNamespace).Update(pod)
	if err != nil {
		return fmt.Errorf("unable to annotate pod, cannot update pod: %s", err)
	}
	return nil
}
