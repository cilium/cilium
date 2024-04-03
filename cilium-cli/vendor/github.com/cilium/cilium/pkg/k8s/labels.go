// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/sirupsen/logrus"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// UseOriginalSourceAddressLabel is the k8s label that can be added to a
// `CiliumEnvoyConfig`. This way the Cilium BPF Metadata listener filter is configured
// to use the original source address when extracting the metadata for a request.
const UseOriginalSourceAddressLabel = "cilium.io/use-original-source-address"

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
	labels := k8sUtils.SanitizePodLabels(objMetaCpy.Labels, k8sNs, pod.Spec.ServiceAccountName, option.Config.ClusterName)

	for _, containers := range pod.Spec.Containers {
		containerPorts = append(containerPorts, containers.Ports...)
	}

	return containerPorts, labels, annotations, nil
}
