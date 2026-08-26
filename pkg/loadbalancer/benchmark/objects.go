// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark

import (
	_ "embed"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTestUtils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

var (
	//go:embed testdata/service.yaml
	serviceYaml []byte

	//go:embed testdata/endpointslice.yaml
	endpointSliceYaml []byte
)

type benchmarkObjectSet struct {
	services         []*slim_corev1.Service
	endpointSlices   []*k8s.Endpoints
	pods             []*slim_corev1.Pod
	lrps             []*ciliumv2.CiliumLocalRedirectPolicy
	backendCount     int
	lrpBackendCounts map[loadbalancer.ServiceName]int
	lrpBackendIPs    map[loadbalancer.ServiceName]map[netip.Addr]struct{}
	lrpBackendLastIP map[loadbalancer.ServiceName]netip.Addr
	lrpServices      map[loadbalancer.ServiceName]loadbalancer.ServiceName
	lrpTargets       map[loadbalancer.ServiceName]loadbalancer.ServiceName
}

func generateBenchmarkObjects(logger *slog.Logger, cfg Config) *benchmarkObjectSet {
	objects := &benchmarkObjectSet{
		services:       make([]*slim_corev1.Service, 0, cfg.Services),
		endpointSlices: make([]*k8s.Endpoints, 0, cfg.Services),
	}
	if cfg.ServiceMatcherLRPs > 0 {
		unmatchedNamespaces := cfg.ServiceMatcherLRPs
		if cfg.ServiceMatcherLRPSharedNamespace {
			unmatchedNamespaces = 1
		}
		podCapacity := cfg.ServiceMatcherLRPs*cfg.LRPBackends + unmatchedNamespaces*cfg.UnmatchedLRPNamespacePods
		objects.pods = make([]*slim_corev1.Pod, 0, podCapacity)
		objects.lrps = make([]*ciliumv2.CiliumLocalRedirectPolicy, 0, cfg.ServiceMatcherLRPs)
		objects.lrpBackendCounts = make(map[loadbalancer.ServiceName]int, cfg.ServiceMatcherLRPs)
		objects.lrpBackendIPs = make(map[loadbalancer.ServiceName]map[netip.Addr]struct{}, cfg.ServiceMatcherLRPs)
		objects.lrpBackendLastIP = make(map[loadbalancer.ServiceName]netip.Addr, cfg.ServiceMatcherLRPs)
		objects.lrpServices = make(map[loadbalancer.ServiceName]loadbalancer.ServiceName, cfg.ServiceMatcherLRPs)
		objects.lrpTargets = make(map[loadbalancer.ServiceName]loadbalancer.ServiceName, cfg.ServiceMatcherLRPs)
	}

	obj, err := k8sTestUtils.DecodeObject(serviceYaml)
	if err != nil {
		panic(err)
	}
	svc := obj.(*slim_corev1.Service)

	svcAddr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		panic(err)
	}

	obj, err = k8sTestUtils.DecodeObject(endpointSliceYaml)
	if err != nil {
		panic(err)
	}
	slice := obj.(*slim_discovery_v1.EndpointSlice)

	sliceAddr, err := netip.ParseAddr(slice.Endpoints[0].Addresses[0])
	if err != nil {
		panic(err)
	}

	for serviceIndex := range cfg.Services {
		tmpSvc := svc.DeepCopy()
		tmpSvcIPString := offsetIPv4(svcAddr, serviceIndex).String()
		tmpSvc.Spec.ClusterIP = tmpSvcIPString
		tmpSvc.Spec.ClusterIPs = []string{tmpSvcIPString}

		tmpSvc.Name = fmt.Sprintf("%s-%06d", svc.Name, serviceIndex)
		if serviceIndex < cfg.ServiceMatcherLRPs && !cfg.ServiceMatcherLRPSharedNamespace {
			// Keep each target service and its LRP backends in a separate namespace.
			// LRP scans every pod in its namespace before applying the endpoint
			// selector, so distinct namespaces isolate each policy's scan.
			tmpSvc.Namespace = fmt.Sprintf("%s-%06d", svc.Namespace, serviceIndex)
		}

		tmpSvc.Spec.Selector = maps.Clone(svc.Spec.Selector)
		selectorValue := fmt.Sprintf("%s-%06d", svc.Spec.Selector["name"], serviceIndex)
		tmpSvc.Spec.Selector["name"] = selectorValue
		if serviceIndex < cfg.ServiceMatcherLRPs {
			// The embedded Service exposes HTTP, so rewrite its single port as DNS
			// for the LRP workload. Use TCP because only the final generated pod
			// exposes dns-tcp, forcing a full named-port scan; every pod exposes
			// UDP/53, which would match immediately.
			tmpSvc.Spec.Ports[0].Name = "dns-tcp"
			tmpSvc.Spec.Ports[0].Port = 53
		}

		tmpSlice := slice.DeepCopy()
		tmpSlice.Namespace = tmpSvc.Namespace
		tmpSlice.Name = fmt.Sprintf("%s-%06d", slice.Name, serviceIndex)
		tmpSlice.Labels = maps.Clone(slice.Labels)
		tmpSlice.Labels["kubernetes.io/service-name"] = tmpSvc.Name
		tmpSlice.Endpoints = make([]slim_discovery_v1.Endpoint, 0, cfg.EndpointsPerService)
		if serviceIndex < cfg.ServiceMatcherLRPs {
			// Kubernetes normally derives the EndpointSlice ports for the Service.
			// The benchmark creates both independently, so mirror the rewritten
			// Service port here.
			portName := "dns-tcp"
			port := int32(53)
			tmpSlice.Ports[0].Name = &portName
			tmpSlice.Ports[0].Port = &port
		}

		for podIndex := range cfg.EndpointsPerService {
			backendIndex := serviceIndex*cfg.EndpointsPerService + podIndex
			podIP := offsetIPv4(sliceAddr, backendIndex).String()

			endpoint := slice.Endpoints[0]
			endpoint.Addresses = []string{podIP}
			tmpSlice.Endpoints = append(tmpSlice.Endpoints, endpoint)
		}

		objects.services = append(objects.services, tmpSvc)
		parsedEndpoints := k8s.ParseEndpointSliceV1(logger, tmpSlice)
		objects.endpointSlices = append(objects.endpointSlices, parsedEndpoints)
		objects.backendCount += countEndpointBackends(parsedEndpoints)
		if serviceIndex < cfg.ServiceMatcherLRPs {
			lrp := newServiceMatcherLRP(tmpSvc.Namespace, tmpSvc.Name, selectorValue, serviceIndex)
			objects.lrps = append(objects.lrps, lrp)
			targetService := loadbalancer.NewServiceName(tmpSvc.Namespace, tmpSvc.Name)
			lrpService := localRedirectServiceName(lrp.Namespace, lrp.Name)
			backendIPs := make(map[netip.Addr]struct{}, cfg.LRPBackends)
			backendCount := 0
			for podIndex := range cfg.LRPBackends {
				backendIndex := cfg.Services*cfg.EndpointsPerService + serviceIndex*cfg.LRPBackends + podIndex
				podIP := offsetIPv4(sliceAddr, backendIndex)
				pod := newPod(tmpSvc.Namespace, selectorValue, serviceIndex, podIndex, cfg.LRPBackends, podIP.String(), nodeTypes.GetName())
				objects.pods = append(objects.pods, pod)
				backendIPs[podIP] = struct{}{}
				count := countPodBackends(pod)
				backendCount += count
				objects.backendCount += count
			}
			objects.lrpBackendCounts[lrpService] = backendCount
			objects.lrpBackendIPs[lrpService] = backendIPs
			objects.lrpBackendLastIP[lrpService] = offsetIPv4(sliceAddr, cfg.Services*cfg.EndpointsPerService+(serviceIndex+1)*cfg.LRPBackends-1)
			objects.lrpServices[targetService] = lrpService
			objects.lrpTargets[lrpService] = targetService
		}
	}

	if cfg.ServiceMatcherLRPs > 0 && cfg.UnmatchedLRPNamespacePods > 0 {
		unmatchedNamespaces := cfg.ServiceMatcherLRPs
		if cfg.ServiceMatcherLRPSharedNamespace {
			unmatchedNamespaces = 1
		}
		for namespaceIndex := range unmatchedNamespaces {
			namespace := svc.Namespace
			if !cfg.ServiceMatcherLRPSharedNamespace {
				namespace = fmt.Sprintf("%s-%06d", svc.Namespace, namespaceIndex)
			}
			for podIndex := range cfg.UnmatchedLRPNamespacePods {
				podIndexInSet := namespaceIndex*cfg.UnmatchedLRPNamespacePods + podIndex
				backendIndex := cfg.Services*cfg.EndpointsPerService + cfg.ServiceMatcherLRPs*cfg.LRPBackends + podIndexInSet
				podIP := offsetIPv4(sliceAddr, backendIndex).String()
				pod := newPod(namespace, "unmatched", cfg.Services+namespaceIndex, podIndex, cfg.UnmatchedLRPNamespacePods, podIP, nodeTypes.GetName())
				pod.Name = fmt.Sprintf("unmatched-%06d-%06d", namespaceIndex, podIndex)
				objects.pods = append(objects.pods, pod)
			}
		}
	}
	return objects
}

func countEndpointBackends(endpoints *k8s.Endpoints) int {
	count := 0
	for _, backend := range endpoints.Backends {
		count += len(backend.Ports)
	}
	return count
}

func countPodBackends(pod *slim_corev1.Pod) int {
	count := 0
	for _, container := range pod.Spec.Containers {
		count += len(container.Ports)
	}
	return count
}

func offsetIPv4(base netip.Addr, offset int) netip.Addr {
	addr := base.As4()
	value := uint64(addr[0])<<24 | uint64(addr[1])<<16 | uint64(addr[2])<<8 | uint64(addr[3])
	value += uint64(offset)
	if value > uint64(^uint32(0)) {
		panic("benchmark IPv4 address range exhausted")
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func newPod(namespace, selectorValue string, serviceIndex, podIndex, podsPerLRP int, podIP, nodeName string) *slim_corev1.Pod {
	ports := []slim_corev1.ContainerPort{{
		Name:          "dns",
		ContainerPort: 53,
		Protocol:      slim_corev1.ProtocolUDP,
	}}
	if podIndex == podsPerLRP-1 {
		// The matching named port is deliberately present only on the final pod.
		// Since LocalPod is ordered by name, this exercises the full linear scan
		// in shouldRedirectFrontend while retaining a node-local-DNS-style policy.
		ports = append(ports, slim_corev1.ContainerPort{
			Name:          "dns-tcp",
			ContainerPort: 53,
			Protocol:      slim_corev1.ProtocolTCP,
		})
	}

	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      fmt.Sprintf("backend-%06d-%06d", serviceIndex, podIndex),
			Namespace: namespace,
			Labels: map[string]string{
				"name": selectorValue,
			},
		},
		Spec: slim_corev1.PodSpec{
			NodeName: nodeName,
			Containers: []slim_corev1.Container{{
				Name:  "backend",
				Ports: ports,
			}},
		},
		Status: slim_corev1.PodStatus{
			Phase:  slim_corev1.PodRunning,
			PodIP:  podIP,
			PodIPs: []slim_corev1.PodIP{{IP: podIP}},
			Conditions: []slim_corev1.PodCondition{{
				Type:   slim_corev1.PodReady,
				Status: slim_corev1.ConditionTrue,
			}},
		},
	}
}

func newServiceMatcherLRP(namespace, serviceName, selectorValue string, serviceIndex int) *ciliumv2.CiliumLocalRedirectPolicy {
	return &ciliumv2.CiliumLocalRedirectPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%06d", benchmarkLRPName, serviceIndex),
			Namespace: namespace,
		},
		Spec: ciliumv2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: ciliumv2.RedirectFrontend{
				ServiceMatcher: &ciliumv2.ServiceInfo{
					Name:      serviceName,
					Namespace: namespace,
				},
			},
			RedirectBackend: ciliumv2.RedirectBackend{
				LocalEndpointSelector: slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"name": selectorValue},
				},
				ToPorts: []ciliumv2.PortInfo{
					{Name: "dns", Port: "53", Protocol: policyapi.ProtoUDP},
					{Name: "dns-tcp", Port: "53", Protocol: policyapi.ProtoTCP},
				},
			},
		},
	}
}

const benchmarkLRPName = "benchmark-lrp"

func localRedirectServiceName(namespace, lrpName string) loadbalancer.ServiceName {
	return loadbalancer.NewServiceName(namespace, lrpName+":local-redirect")
}
