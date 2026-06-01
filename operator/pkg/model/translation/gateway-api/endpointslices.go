// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/shortener"
)

const (
	EndpointSliceManagedByLabel   = "endpointslice.kubernetes.io/managed-by"
	EndpointSliceManagedByValue   = "cilium-operator"
	EndpointSliceServiceNameLabel = "kubernetes.io/service-name"
	BackendServiceAnnotation      = "gateway.cilium.io/backend-service"
	BackendPortAnnotation         = "gateway.cilium.io/backend-port"
	EndpointSliceWeightAnnotation = "service.cilium.io/weight"
	endpointSliceFamilySuffixIPv4 = "ipv4"
	endpointSliceFamilySuffixIPv6 = "ipv6"
)

// desiredL4EndpointSlices builds skeleton EndpointSlices per (backend Service,
// backendRef.port, IP family). Listeners/routes sharing that tuple are merged
// into one slice with one Ports entry per listener; endpointSliceReconciler
// later resolves the numeric Port and populates .endpoints.
func (t *gatewayAPITranslator) desiredL4EndpointSlices(listeners []model.L4Listener, source *model.FullyQualifiedResource, lbSvc *corev1.Service) []*discoveryv1.EndpointSlice {
	if len(listeners) == 0 || source == nil || lbSvc == nil {
		return nil
	}

	families := enabledAddressTypes(lbSvc)
	if len(families) == 0 {
		return nil
	}

	ownerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       source.Kind,
		Name:       source.Name,
		UID:        types.UID(source.UID),
		Controller: ptr.To(true),
	}
	shortGw := shortener.ShortenK8sResourceName(source.Name)
	svcName := lbSvc.Name

	type groupKey struct {
		backendNs   string
		backendName string
		backendPort uint32
		protocol    corev1.Protocol
		family      discoveryv1.AddressType
	}
	type group struct {
		key      groupKey
		backend  model.Backend
		listener model.L4Listener
		ports    []discoveryv1.EndpointPort
		seenPort map[string]struct{}
	}

	groups := map[groupKey]*group{}
	var order []groupKey

	for _, l := range listeners {
		listener := l
		portName := listenerPortName(listener)
		protocol := corev1.ProtocolTCP
		if listener.GetProtocol() == model.L4ProtocolUDP {
			protocol = corev1.ProtocolUDP
		}
		listenerPort := int32(listener.GetPort())

		for _, route := range listener.Routes {
			for _, backend := range route.Backends {
				b := backend
				backendPort := backendTargetPort(listener, b)

				for _, family := range families {
					k := groupKey{
						backendNs:   b.Namespace,
						backendName: b.Name,
						backendPort: backendPort,
						protocol:    protocol,
						family:      family,
					}
					g, ok := groups[k]
					if !ok {
						g = &group{
							key:      k,
							backend:  b,
							listener: listener,
							seenPort: map[string]struct{}{},
						}
						groups[k] = g
						order = append(order, k)
					}
					if _, dup := g.seenPort[portName]; dup {
						continue
					}
					g.seenPort[portName] = struct{}{}
					g.ports = append(g.ports, discoveryv1.EndpointPort{
						Name:     ptr.To(portName),
						Port:     ptr.To(listenerPort),
						Protocol: ptr.To(protocol),
					})
				}
			}
		}
	}

	slicesOut := make([]*discoveryv1.EndpointSlice, 0, len(order))
	for _, k := range order {
		g := groups[k]
		// Stable order so mergeEndpointPorts pairs existing/desired by index.
		sort.SliceStable(g.ports, func(i, j int) bool {
			return ptr.Deref(g.ports[i].Name, "") < ptr.Deref(g.ports[j].Name, "")
		})
		slicesOut = append(slicesOut, buildEndpointSlice(buildEPSArgs{
			svcName:     svcName,
			gwShort:     shortGw,
			namespace:   source.Namespace,
			backend:     g.backend,
			family:      g.key.family,
			backendPort: g.key.backendPort,
			protocol:    g.key.protocol,
			ports:       g.ports,
			ownerRef:    ownerRef,
		}))
	}

	sort.SliceStable(slicesOut, func(i, j int) bool { return slicesOut[i].Name < slicesOut[j].Name })
	return slicesOut
}

type buildEPSArgs struct {
	svcName     string
	gwShort     string
	namespace   string
	backend     model.Backend
	family      discoveryv1.AddressType
	backendPort uint32
	protocol    corev1.Protocol
	ports       []discoveryv1.EndpointPort
	ownerRef    metav1.OwnerReference
}

func buildEndpointSlice(args buildEPSArgs) *discoveryv1.EndpointSlice {
	familySuffix := endpointSliceFamilySuffixIPv4
	if args.family == discoveryv1.AddressTypeIPv6 {
		familySuffix = endpointSliceFamilySuffixIPv6
	}

	hash := backendHash(args.backend, args.backendPort, args.protocol)
	rawName := fmt.Sprintf("%s-%s-%s", args.svcName, hash, familySuffix)
	name := shortener.ShortenK8sResourceName(rawName)

	annotations := map[string]string{
		BackendServiceAnnotation: args.backend.Namespace + "/" + args.backend.Name,
		BackendPortAnnotation:    strconv.FormatUint(uint64(args.backendPort), 10),
	}
	if w := normalizedWeight(args.backend.Weight); w != nil {
		annotations[EndpointSliceWeightAnnotation] = strconv.FormatInt(int64(*w), 10)
	}

	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: args.namespace,
			Labels: map[string]string{
				EndpointSliceServiceNameLabel: args.svcName,
				EndpointSliceManagedByLabel:   EndpointSliceManagedByValue,
				gatewayNameLabel:              args.gwShort,
			},
			Annotations:     annotations,
			OwnerReferences: []metav1.OwnerReference{args.ownerRef},
		},
		AddressType: args.family,
		Ports:       args.ports,
		Endpoints:   []discoveryv1.Endpoint{},
	}
}

// listenerPortName mirrors the ServicePort.Name produced by toServicePorts.
func listenerPortName(l model.L4Listener) string {
	if l.GetProtocol() == model.L4ProtocolUDP {
		return fmt.Sprintf("port-%d-udp", l.GetPort())
	}
	return fmt.Sprintf("port-%d", l.GetPort())
}

// backendTargetPort returns the port on the backend Pods. If unset on the
// backendRef, the listener port is used.
func backendTargetPort(listener model.L4Listener, b model.Backend) uint32 {
	if b.Port != nil && b.Port.Port != 0 {
		return b.Port.Port
	}
	return listener.Port
}

func enabledAddressTypes(svc *corev1.Service) []discoveryv1.AddressType {
	if svc == nil {
		return nil
	}
	if len(svc.Spec.IPFamilies) == 0 {
		return []discoveryv1.AddressType{discoveryv1.AddressTypeIPv4}
	}
	res := make([]discoveryv1.AddressType, 0, len(svc.Spec.IPFamilies))
	for _, f := range svc.Spec.IPFamilies {
		switch f {
		case corev1.IPv4Protocol:
			res = append(res, discoveryv1.AddressTypeIPv4)
		case corev1.IPv6Protocol:
			res = append(res, discoveryv1.AddressTypeIPv6)
		}
	}
	return res
}

// backendHash keys the slice name on (backend Service, backendRef.port,
// protocol) so listeners/routes sharing that tuple share a slice, while TCP and
// UDP for the same backend/port resolve to distinct slices.
func backendHash(b model.Backend, port uint32, protocol corev1.Protocol) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s/%s|%d|%s", b.Namespace, b.Name, port, protocol)
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// normalizedWeight caps Gateway API weight (0..1_000_000) to uint16, the range
// honored by service.cilium.io/weight (cilium/cilium#46061).
func normalizedWeight(w *int32) *uint16 {
	if w == nil {
		return nil
	}
	return ptr.To(uint16(min(*w, 65535)))
}
