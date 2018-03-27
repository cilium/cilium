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

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/uuid"

	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodEndpoint is the interface that the endpoint representing a pod has to implement
type PodEndpoint interface {
	// GetK8sNamespace returns the name of the namespace
	GetK8sNamespace() string

	// GetK8sPodName returns the name of the pod
	GetK8sPodName() string

	// StringID returns the ID of the endpoint
	StringID() string
}

// AnnotatePod adds a Kubernetes annotation with key annotationKey and value
// annotationValue
func AnnotatePod(e PodEndpoint, annotationKey, annotationValue string) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.EndpointID:            e.StringID(),
		logfields.K8sNamespace:          e.GetK8sNamespace(),
		logfields.K8sPodName:            e.GetK8sPodName(),
		logfields.K8sIdentityAnnotation: annotationKey,
		logfields.RetryUUID:             uuid.NewUUID(),
	})

	pod, err := Client().CoreV1().Pods(e.GetK8sNamespace()).Get(e.GetK8sPodName(), meta_v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to annotate pod, cannot retrieve pod: %s", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations[annotationKey] = annotationValue
	pod, err = Client().CoreV1().Pods(e.GetK8sNamespace()).Update(pod)
	if err != nil {
		return fmt.Errorf("unable to annotate pod, cannot update pod: %s", err)
	}

	scopedLog.Debugf("Successfully annotated pod with %s=%s", annotationKey, annotationValue)
	return nil
}
