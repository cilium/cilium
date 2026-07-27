// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"

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

// NamedPortsIdentityLabels returns the generated identity labels for named ports.
// Use delimiters allowed in k8s label values:
// '.' - separate fields
// '_' - separate multiple values
//
// Note that a single named port always fits into a single label, as the named port name is limited
// to 15 characters (IANA service name limitation), and a single label can be upto 63 characters
// long.
func NamedPortsIdentityLabels(namedPorts ciliumTypes.NamedPortMap) ciliumLabels.LabelArray {
	if len(namedPorts) == 0 {
		return nil
	}

	var labels ciliumLabels.LabelArray
	var value strings.Builder

	appendLabel := func() {
		labels = append(labels, ciliumLabels.NewLabel(
			ciliumio.NamedPortsIdentityLabelNameForIndex(len(labels)),
			value.String(),
			ciliumLabels.LabelSourceGenerated,
		))
		value.Reset()
	}

	for _, name := range slices.Sorted(maps.Keys(namedPorts)) {
		port := namedPorts[name]
		portProto := port.Proto.String()
		portNum := strconv.Itoa(int(port.Port))

		partLen := len(name) + 1 + len(portProto) + 1 + len(portNum)
		if value.Len() > 0 && value.Len()+1+partLen > content.LabelValueMaxLength {
			appendLabel()
		}

		if value.Len() > 0 {
			value.WriteByte('_')
		}
		value.WriteString(name)
		value.WriteByte('.')
		value.WriteString(portProto)
		value.WriteByte('.')
		value.WriteString(portNum)
	}
	if value.Len() > 0 {
		appendLabel()
	}
	return labels
}
