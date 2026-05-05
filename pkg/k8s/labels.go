// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
)

// UseOriginalSourceAddressLabel is the k8s label that can be added to a
// `CiliumEnvoyConfig`. This way the Cilium BPF Metadata listener filter is configured
// to use the original source address when extracting the metadata for a request.
//
// Deprecated: use the corresponding annotation
const UseOriginalSourceAddressLabel = "cilium.io/use-original-source-address"

type nameLabelsGetter interface {
	GetName() string
	GetLabels() map[string]string
}

// GetPodMetadata returns the named ports, labels and annotations of the pod
// with the given namespace / name.
func GetPodMetadata(logger *slog.Logger, k8sNs nameLabelsGetter, pod *slim_corev1.Pod) (namedPorts ciliumTypes.NamedPortMap, lbls map[string]string) {
	namespace := pod.Namespace
	logger.Debug(
		"Connecting to k8s local stores to retrieve labels for pod",
		logfields.K8sNamespace, namespace,
		logfields.K8sPodName, pod.Name,
	)

	objMetaCpy := pod.ObjectMeta.DeepCopy()
	labels := k8sUtils.SanitizePodLabels(objMetaCpy.Labels, k8sNs, pod.Spec.ServiceAccountName, option.Config.ClusterName)

	namedPorts = make(ciliumTypes.NamedPortMap)
	for _, containers := range pod.Spec.Containers {
		for _, port := range containers.Ports {
			if port.Name != "" {
				if err := namedPorts.AddPort(port.Name, int(port.ContainerPort), string(port.Protocol)); err != nil {
					logger.Warn("Adding named port failed", logfields.Error, err)
				}
			}
		}
	}

	return namedPorts, labels
}

// NamedPortsIdentityLabel returns the generated identity label for named ports.
func NamedPortsIdentityLabel(namedPorts ciliumTypes.NamedPortMap) (ciliumLabels.Label, bool) {
	if len(namedPorts) == 0 {
		return ciliumLabels.Label{}, false
	}

	var value strings.Builder
	for i, name := range slices.Sorted(maps.Keys(namedPorts)) {
		if i > 0 {
			value.WriteByte(',')
		}
		value.WriteString(name)
		value.WriteByte(':')
		value.WriteString(namedPorts[name].Proto.String())
		value.WriteByte(':')
		value.WriteString(strconv.Itoa(int(namedPorts[name].Port)))
	}
	return ciliumLabels.NewLabel(ciliumio.NamedPortsIdentityLabelName, value.String(), ciliumLabels.LabelSourceGenerated), true
}
