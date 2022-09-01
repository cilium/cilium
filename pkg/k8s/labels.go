// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
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
func isInjectedWithIstioSidecarProxy(scopedLog *logrus.Entry, pod *slim_corev1.Pod) bool {
	istioStatusString, ok := pod.Annotations[AnnotationIstioSidecarStatus]
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

		for _, mountPath := range container.VolumeMounts {
			if mountPath.MountPath != "/var/run/cilium" {
				continue
			}
			scopedLog.Debug("istio-proxy container has volume mounted into /var/run/cilium")

			return true
		}
	}

	scopedLog.Debug("No Cilium-compatible istio-proxy container found")
	return false
}

// GetPodMetadata returns the labels and annotations of the pod with the given
// namespace / name.
func GetPodMetadata(k8sNs *slim_corev1.Namespace, pod *slim_corev1.Pod) (containerPorts []slim_corev1.ContainerPort, lbls map[string]string, retAnno map[string]string, retErr error) {
	namespace := pod.Namespace
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace: namespace,
		logfields.K8sPodName:   pod.Name,
	})
	scopedLog.Debug("Connecting to k8s local stores to retrieve labels for pod")

	objMetaCpy := pod.ObjectMeta.DeepCopy()
	annotations := objMetaCpy.Annotations
	k8sLabels := filterPodLabels(objMetaCpy.Labels)

	for k, v := range k8sNs.GetLabels() {
		k8sLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
	}
	k8sLabels[k8sConst.PodNamespaceLabel] = namespace

	if pod.Spec.ServiceAccountName != "" {
		k8sLabels[k8sConst.PolicyLabelServiceAccount] = pod.Spec.ServiceAccountName
	} else {
		delete(k8sLabels, k8sConst.PolicyLabelServiceAccount)
	}

	// If the pod has been injected with an Istio sidecar proxy compatible with
	// Cilium, add a label to notify that.
	// If the pod already contains that label to explicitly enable or disable
	// the sidecar proxy mode, keep it as is.
	if val, ok := objMetaCpy.Labels[k8sConst.PolicyLabelIstioSidecarProxy]; ok {
		k8sLabels[k8sConst.PolicyLabelIstioSidecarProxy] = val
	} else if isInjectedWithIstioSidecarProxy(scopedLog, pod) {
		k8sLabels[k8sConst.PolicyLabelIstioSidecarProxy] = "true"
	}

	k8sLabels[k8sConst.PolicyLabelCluster] = option.Config.ClusterName

	for _, containers := range pod.Spec.Containers {
		for _, cp := range containers.Ports {
			containerPorts = append(containerPorts, cp)
		}
	}

	return containerPorts, k8sLabels, annotations, nil
}

// filterPodLabels returns a copy of the given labels map, without the labels owned by Cilium.
func filterPodLabels(labels map[string]string) map[string]string {
	res := map[string]string{}
	for k, v := range labels {
		if strings.HasPrefix(k, k8sConst.LabelPrefix) {
			continue
		}
		res[k] = v
	}
	return res
}
