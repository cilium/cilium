// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type portReference struct {
	number uint16
	name   string
}

func validateRXQueueConfig(config *types.RXQueueConfig) error {
	if config == nil {
		return fmt.Errorf("%w: RX queue endpoint is required", errUnexpectedInput)
	}

	if config.PodEndpoint == nil {
		return fmt.Errorf("%w: podEndpoint is required", errUnexpectedInput)
	}
	if _, err := parsePortReference(config.PodEndpoint.Port); err != nil {
		return fmt.Errorf("%w: invalid podEndpoint port: %w", errUnexpectedInput, err)
	}
	if err := validateRXQueueProtocol(config.PodEndpoint.Protocol); err != nil {
		return fmt.Errorf("%w: invalid podEndpoint protocol: %w", errUnexpectedInput, err)
	}

	return nil
}

func validateRXQueueProtocol(protocol corev1.Protocol) error {
	switch protocol {
	case corev1.ProtocolTCP, corev1.ProtocolUDP:
		return nil
	default:
		return fmt.Errorf("protocol must be TCP or UDP, got %q", protocol)
	}
}

func parsePortReference(value string) (portReference, error) {
	if value == "" {
		return portReference{}, fmt.Errorf("port is required")
	}

	if strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return portReference{}, fmt.Errorf("port number %q must be between 1 and 65535", value)
		}
		return portReference{number: uint16(port)}, nil
	}

	if errs := validation.IsValidPortName(value); len(errs) != 0 {
		return portReference{}, fmt.Errorf("invalid port name %q: %s", value, strings.Join(errs, "; "))
	}
	return portReference{name: value}, nil
}

// resolveRXQueueFlows resolves traffic selectors against the supplied endpoint
// addresses. The Pod is used only to resolve named ports.
func resolveRXQueueFlows(pod *slim_corev1.Pod, config *types.RXQueueConfig, addresses []netip.Addr) ([]types.RXQueueFlow, error) {
	if err := validateRXQueueConfig(config); err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("Pod %s/%s has no CNI attachment addresses", pod.Namespace, pod.Name)
	}

	port, err := podEndpointPort(pod, config.PodEndpoint)
	if err != nil {
		return nil, err
	}
	var flows []types.RXQueueFlow
	for _, ip := range addresses {
		if !ip.IsValid() {
			return nil, fmt.Errorf("Pod %s/%s has an invalid CNI attachment address", pod.Namespace, pod.Name)
		}
		flows = append(flows, types.RXQueueFlow{
			DestinationIP:   ip.Unmap(),
			DestinationPort: port,
			Protocol:        config.PodEndpoint.Protocol,
		})
	}

	slices.SortFunc(flows, func(a, b types.RXQueueFlow) int {
		return cmp.Or(
			a.DestinationIP.Compare(b.DestinationIP),
			cmp.Compare(a.DestinationPort, b.DestinationPort),
			cmp.Compare(a.Protocol, b.Protocol),
		)
	})
	return slices.Compact(flows), nil
}

func podEndpointPort(pod *slim_corev1.Pod, endpoint *types.RXQueuePodEndpoint) (uint16, error) {
	port, err := parsePortReference(endpoint.Port)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid podEndpoint port: %w", errUnexpectedInput, err)
	}
	if port.name == "" {
		return port.number, nil
	}

	for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
		for _, containerPort := range container.Ports {
			protocol := corev1.Protocol(containerPort.Protocol)
			if protocol == "" {
				protocol = corev1.ProtocolTCP
			}
			if containerPort.Name == port.name && protocol == endpoint.Protocol &&
				containerPort.ContainerPort > 0 && containerPort.ContainerPort <= math.MaxUint16 {
				return uint16(containerPort.ContainerPort), nil
			}
		}
	}
	return 0, fmt.Errorf("Pod %s/%s has no %s port named %q", pod.Namespace, pod.Name, endpoint.Protocol, port.name)
}
