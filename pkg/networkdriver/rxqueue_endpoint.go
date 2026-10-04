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

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
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

	switch {
	case config.PodEndpoint == nil && config.ServiceEndpoint == nil:
		return fmt.Errorf("%w: exactly one of podEndpoint or serviceEndpoint is required", errUnexpectedInput)
	case config.PodEndpoint != nil && config.ServiceEndpoint != nil:
		return fmt.Errorf("%w: podEndpoint and serviceEndpoint are mutually exclusive", errUnexpectedInput)
	case config.PodEndpoint != nil:
		if _, err := parsePortReference(config.PodEndpoint.Port); err != nil {
			return fmt.Errorf("%w: invalid podEndpoint port: %w", errUnexpectedInput, err)
		}
		if err := validateRXQueueProtocol(config.PodEndpoint.Protocol); err != nil {
			return fmt.Errorf("%w: invalid podEndpoint protocol: %w", errUnexpectedInput, err)
		}
	case config.ServiceEndpoint.ServiceName == "":
		return fmt.Errorf("%w: serviceEndpoint serviceName is required", errUnexpectedInput)
	default:
		if _, err := parsePortReference(config.ServiceEndpoint.Port); err != nil {
			return fmt.Errorf("%w: invalid serviceEndpoint port: %w", errUnexpectedInput, err)
		}
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

type rxQueueFlowResolver struct {
	services             statedb.Table[*loadbalancer.Service]
	frontends            statedb.Table[*loadbalancer.Frontend]
	nodeAddresses        statedb.Table[datapathTables.NodeAddress]
	externalClusterIP    bool
	kubeProxyReplacement bool
}

// resolve returns the traffic to steer to the Pod's RX queue and watches the
// Service and node-address state needed to resolve it again after changes.
func (r rxQueueFlowResolver) resolve(
	txn statedb.ReadTxn,
	ws *statedb.WatchSet,
	pod *slim_corev1.Pod,
	config *types.RXQueueConfig,
) ([]types.RXQueueFlow, error) {
	ips, err := rxQueuePodIPs(pod)
	if err != nil {
		return nil, err
	}

	var flows []types.RXQueueFlow
	if config.PodEndpoint != nil {
		port, err := podEndpointPort(pod, config.PodEndpoint)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			flows = append(flows, types.RXQueueFlow{
				DestinationIP:   ip,
				DestinationPort: port,
				Protocol:        config.PodEndpoint.Protocol,
			})
		}
	} else {
		flows, err = r.serviceEndpointFlows(txn, ws, pod.Namespace, ips, config.ServiceEndpoint)
		if err != nil {
			return nil, err
		}
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

func rxQueuePodIPs(pod *slim_corev1.Pod) ([]netip.Addr, error) {
	var ips []netip.Addr
	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			return nil, fmt.Errorf("Pod %s/%s has invalid IP %q: %w", pod.Namespace, pod.Name, podIP.IP, err)
		}
		if ip = ip.Unmap(); !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("Pod %s/%s has no IP addresses", pod.Namespace, pod.Name)
	}
	return ips, nil
}

func podEndpointPort(pod *slim_corev1.Pod, endpoint *types.RXQueuePodEndpoint) (uint16, error) {
	port, err := parsePortReference(endpoint.Port)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid podEndpoint port: %w", errUnexpectedInput, err)
	}
	if port.name == "" {
		return port.number, nil
	}

	for _, containers := range [][]slim_corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, container := range containers {
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
	}
	return 0, fmt.Errorf("Pod %s/%s has no %s port named %q", pod.Namespace, pod.Name, endpoint.Protocol, port.name)
}

// serviceEndpointFlows matches the tuples on the wire before Service
// translation. All backends selected for a frontend must belong to this Pod;
// externalTrafficPolicy=Local alone does not distinguish local Pods.
func (r rxQueueFlowResolver) serviceEndpointFlows(
	txn statedb.ReadTxn,
	ws *statedb.WatchSet,
	namespace string,
	ips []netip.Addr,
	endpoint *types.RXQueueServiceEndpoint,
) ([]types.RXQueueFlow, error) {
	if !r.kubeProxyReplacement {
		return nil, fmt.Errorf("serviceEndpoint requires kube-proxy replacement")
	}
	name := loadbalancer.NewServiceName(namespace, endpoint.ServiceName)
	service, _, watch, found := r.services.GetWatch(txn, loadbalancer.ServiceByName(name))
	ws.Add(watch)
	if !found {
		return nil, fmt.Errorf("Service %s was not found", name)
	}
	if service.ExtTrafficPolicy != loadbalancer.SVCTrafficPolicyLocal {
		return nil, fmt.Errorf("Service %s requires externalTrafficPolicy: Local", name)
	}
	portName, err := servicePortName(service, endpoint.Port)
	if err != nil {
		return nil, err
	}

	frontends, watch := r.frontends.ListWatch(txn, loadbalancer.FrontendByServiceName(name))
	ws.Add(watch)
	var flows []types.RXQueueFlow
	for frontend := range frontends {
		if string(frontend.PortName) != portName || frontend.ServicePort != service.PortNames[portName] ||
			frontend.Address.Scope() != loadbalancer.ScopeExternal {
			continue
		}
		switch frontend.Type {
		case loadbalancer.SVCTypeClusterIP:
			if !r.externalClusterIP {
				continue
			}
		case loadbalancer.SVCTypeNodePort, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTypeExternalIPs:
		default:
			continue
		}
		if frontend.Status.Kind != reconciler.StatusKindDone || frontend.ID == 0 {
			return nil, fmt.Errorf("Service %s frontend %s is not programmed", name, frontend.Address)
		}
		if frontend.RedirectTo != nil || service.ProxyRedirects.Redirects(frontend.ServicePort) {
			return nil, fmt.Errorf("Service %s frontend %s redirects to another service or proxy", name, frontend.Address)
		}
		foundBackend := false
		for backend := range frontend.Backends {
			if backend.ClusterID != 0 || !slices.Contains(ips, backend.Address.Addr().Unmap()) {
				return nil, fmt.Errorf("Service %s frontend %s can route to a Pod other than the Pod holding this RX queue claim", name, frontend.Address)
			}
			foundBackend = true
		}
		if !foundBackend {
			return nil, fmt.Errorf("Service %s frontend %s has no backends", name, frontend.Address)
		}
		protocol := corev1.Protocol(frontend.Address.Protocol())
		if err := validateRXQueueProtocol(protocol); err != nil {
			return nil, fmt.Errorf("Service %s port %s: %w", name, endpoint.Port, err)
		}
		if frontend.Type == loadbalancer.SVCTypeNodePort {
			flows = append(flows, r.nodePortFlows(txn, ws, frontend)...)
			continue
		}
		flows = append(flows, types.RXQueueFlow{
			DestinationIP:   frontend.Address.Addr().Unmap(),
			DestinationPort: frontend.Address.Port(),
			Protocol:        protocol,
		})
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("Service %s has no externally reachable frontend for port %s", name, endpoint.Port)
	}
	return flows, nil
}

func (r rxQueueFlowResolver) nodePortFlows(txn statedb.ReadTxn, ws *statedb.WatchSet, frontend *loadbalancer.Frontend) []types.RXQueueFlow {
	addresses, watch := r.nodeAddresses.ListWatch(txn, datapathTables.NodeAddressesByNodePort(true))
	ws.Add(watch)
	var flows []types.RXQueueFlow
	for address := range addresses {
		if address.Addr.Is6() != frontend.Address.IsIPv6() {
			continue
		}
		// Match the BPF NodePort expansion: a concrete frontend owns its tuple
		// in preference to a wildcard NodePort, even if it belongs to this Service.
		addr := loadbalancer.NewL3n4Addr(frontend.Address.Protocol(), cmtypes.AddrClusterFrom(address.Addr, 0),
			frontend.Address.Port(), frontend.Address.Scope())
		_, _, watch, found := r.frontends.GetWatch(txn, loadbalancer.FrontendByAddress(addr))
		ws.Add(watch)
		if found {
			continue
		}
		flows = append(flows, types.RXQueueFlow{
			DestinationIP:   address.Addr.Unmap(),
			DestinationPort: frontend.Address.Port(),
			Protocol:        corev1.Protocol(frontend.Address.Protocol()),
		})
	}
	return flows
}

func servicePortName(service *loadbalancer.Service, value string) (string, error) {
	port, err := parsePortReference(value)
	if err != nil {
		return "", fmt.Errorf("%w: invalid serviceEndpoint port: %w", errUnexpectedInput, err)
	}
	if port.name != "" {
		if _, found := service.PortNames[port.name]; !found {
			return "", fmt.Errorf("Service %s has no port %q", service.Name, value)
		}
		return port.name, nil
	}

	var names []string
	for name, number := range service.PortNames {
		if number == port.number {
			names = append(names, name)
		}
	}
	switch len(names) {
	case 0:
		return "", fmt.Errorf("Service %s has no port %q", service.Name, value)
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("Service %s has multiple ports numbered %s; select one by name", service.Name, value)
	}
}
