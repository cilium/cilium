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

package k8s

import (
	"regexp"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// AnnotationIstioSidecarStatus is the annotation added by Istio into a pod
	// when it is injected with a sidecar proxy.
	// Since Istio 0.5.0, the value of this annotation is a serialized JSON object
	// with the following structure ("imagePullSecrets" was added in Istio 0.8.0):
	//
	//     {
	//         "version": "0213afe1274259d2f23feb4820ad2f8eb8609b84a5538e5f51f711545b6bde88",
	//         "initContainers": ["sleep", "istio-init"],
	//         "containers": ["istio-proxy"],
	//         "volumes": ["cilium-unix-sock-dir", "istio-envoy", "istio-certs"],
	//         "imagePullSecrets": null
	//     }
	AnnotationIstioSidecarStatus = "sidecar.istio.io/status"

	// DefaultSidecarIstioProxyImageRegexp is the default regexp compiled into
	// SidecarIstioProxyImageRegexp.
	DefaultSidecarIstioProxyImageRegexp = "cilium/istio_proxy"
)

var (
	// SidecarIstioProxyImageRegexp is the regular expression matching
	// compatible Istio sidecar istio-proxy container image names.
	// This is set by the "sidecar-istio-proxy-image" configuration flag.
	SidecarIstioProxyImageRegexp = regexp.MustCompile(DefaultSidecarIstioProxyImageRegexp)
)

// isInjectedWithIstioSidecarProxy returns whether the given pod has been
// injected by Istio with a sidecar proxy that is compatible with Cilium.
func isInjectedWithIstioSidecarProxy(scopedLog *logrus.Entry, pod *corev1.Pod) bool {
	istioStatusString, ok := pod.GetAnnotations()[AnnotationIstioSidecarStatus]
	if !ok {
		// Istio's injection annotation was not found.
		scopedLog.Debugf("No %s annotation", AnnotationIstioSidecarStatus)
		return false
	}

	scopedLog.Debugf("Found %s annotation with value: %s",
		AnnotationIstioSidecarStatus, istioStatusString)

	// Check that there's an "istio-proxy" container that uses an image
	// compatible with Cilium.
	for _, container := range pod.Spec.Containers {
		if container.Name != "istio-proxy" {
			continue
		}
		scopedLog.Debug("Found istio-proxy container in pod")

		if !SidecarIstioProxyImageRegexp.MatchString(container.Image) {
			continue
		}
		scopedLog.Debugf("istio-proxy container runs Cilium-compatible image: %s", container.Image)

		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/var/run/cilium" {
				continue
			}
			scopedLog.Debug("istio-proxy container has volume mounted into /var/run/cilium")

			return true
		}
	}

	scopedLog.Debug("No Cilium-compatible istio-proxy container found")
	return false
}

// GetPodLabels returns the labels of a pod
func GetPodLabels(namespace, podName string) (map[string]string, error) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace: namespace,
		logfields.K8sPodName:   podName,
	})
	scopedLog.Debug("Connecting to k8s apiserver to retrieve labels for pod")

	result, err := Client().CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Also get all labels from the namespace where the pod is running
	k8sNs, err := Client().CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	k8sLabels := result.GetLabels()
	if k8sLabels == nil {
		k8sLabels = map[string]string{}
	}
	for k, v := range k8sNs.GetLabels() {
		k8sLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
	}
	k8sLabels[k8sConst.PodNamespaceLabel] = namespace

	if result.Spec.ServiceAccountName != "" {
		k8sLabels[k8sConst.PolicyLabelServiceAccount] = result.Spec.ServiceAccountName
	} else {
		delete(k8sLabels, k8sConst.PolicyLabelServiceAccount)
	}

	// If the pod has been injected with an Istio sidecar proxy compatible with
	// Cilium, add a label to notify that.
	// If the pod already contains that label to explicitly enable or disable
	// the sidecar proxy mode, keep it as is.
	if _, ok := k8sLabels[k8sConst.PolicyLabelIstioSidecarProxy]; !ok &&
		isInjectedWithIstioSidecarProxy(scopedLog, result) {
		k8sLabels[k8sConst.PolicyLabelIstioSidecarProxy] = "true"
	}

	k8sLabels[k8sConst.PolicyLabelCluster] = option.Config.ClusterName

	return k8sLabels, nil
}
