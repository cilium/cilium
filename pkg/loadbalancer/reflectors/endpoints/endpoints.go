// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoints

import (
	"iter"
	"log/slog"
	"slices"
	"sync"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	ingressDummyAddress = cmtypes.MustParseAddrCluster("192.192.192.192")
	ingressDummyPort    = uint16(9999)
)

func isIngressDummyEndpoint(l3n4Addr loadbalancer.L3n4Addr) bool {
	// The ingress and gateway-api controllers (operator/pkg/model/translation/{gateway-api,ingress}) create
	// a dummy endpoint to force Cilium to reconcile the service. This is no longer required with this new
	// control-plane, but due to rolling upgrades we cannot remove it immediately. Hence we have the
	// special handling here to just ignore this endpoint to avoid populating the tables with unnecessary
	// data.
	return l3n4Addr.AddrCluster() == ingressDummyAddress && l3n4Addr.Port() == ingressDummyPort
}

type Endpoints struct {
	Name        string
	ServiceName loadbalancer.ServiceName
	Backends    map[cmtypes.AddrCluster]*k8s.Backend
}

// AllEndpoints holds one or more [k8s.Endpoints] that target the same service within a single buffer.
// This type is designed to avoid allocations for the usual case of single endpoint slice per service.
type AllEndpoints struct {
	head Endpoints
	tail []Endpoints
}

func (ae AllEndpoints) Insert(deleted bool, ep *k8s.Endpoints) AllEndpoints {
	ev := Endpoints{
		Name:        ep.EndpointSliceName,
		ServiceName: ep.ServiceName,
	}
	if !deleted {
		ev.Backends = ep.Backends
	}

	if ae.head.Name == "" || ae.head.Name == ev.Name {
		ae.head = ev
		return ae
	}
	for i, x := range ae.tail {
		if ev.Name == x.Name {
			ae.tail[i] = ev
			return ae
		}
	}
	ae.tail = append(ae.tail, ev)
	return ae
}

func (ae *AllEndpoints) All() iter.Seq[Endpoints] {
	return func(yield func(Endpoints) bool) {
		if ae.head.Name != "" {
			if !yield(ae.head) {
				return
			}
		}
		for _, ep := range ae.tail {
			if !yield(ep) {
				return
			}
		}
	}
}

func (ae *AllEndpoints) Backends() iter.Seq2[cmtypes.AddrCluster, *k8s.Backend] {
	return func(yield func(cmtypes.AddrCluster, *k8s.Backend) bool) {
		for ep := range ae.All() {
			for addr, be := range ep.Backends {
				if !yield(addr, be) {
					return
				}
			}
		}
	}
}

func Convert(rawlog *slog.Logger, cfg loadbalancer.ExternalConfig, svcName loadbalancer.ServiceName, bes iter.Seq2[cmtypes.AddrCluster, *k8s.Backend]) iter.Seq[loadbalancer.Backend] {
	return func(yield func(be loadbalancer.Backend) bool) {
		// Lazily construct the augmented logger as we very rarely log here.
		log := sync.OnceValue(func() *slog.Logger {
			return rawlog.With(
				logfields.Service, svcName.Name,
				logfields.K8sNamespace, svcName.Namespace,
			)
		})

		for addrCluster, be := range bes {
			if (!cfg.EnableIPv6 && addrCluster.Is6()) || (!cfg.EnableIPv4 && addrCluster.Is4()) {
				log().Debug(
					"Skipping Backend due to disabled IP family",
					logfields.IPv4, cfg.EnableIPv4,
					logfields.IPv6, cfg.EnableIPv6,
					logfields.Address, addrCluster,
				)
				continue
			}
			for l4Addr, portNames := range be.Ports {
				l3n4Addr := loadbalancer.NewL3n4Addr(
					l4Addr.Protocol,
					addrCluster,
					l4Addr.Port,
					loadbalancer.ScopeExternal,
				)
				if isIngressDummyEndpoint(l3n4Addr) {
					continue
				}

				// Filter out the unnamed port, if present
				if idx := slices.Index(portNames, ""); idx != -1 {
					if len(portNames) == 1 {
						portNames = nil
					} else {
						portNames = slices.Concat(portNames[:idx], portNames[idx+1:])
					}
				}

				var state loadbalancer.BackendState
				switch {
				case be.Maintenance:
					state = loadbalancer.BackendStateMaintenance
				case be.Conditions.IsReady():
					// A backend that is ready (regardless of serving and terminating) is considered
					// active. We may see backends that are ready+terminating if 'PublishNotReadyAddresses'
					// is true. While it would be more logical to set this as terminating, we're following
					// kube-proxy here and considering it as an active backend and not ignoring it even when
					// other active backends are available.
					//
					// See also kube-proxy implementation at:
					// https://github.com/kubernetes/kubernetes/blob/790393ae92e97262827d4f1fba24e8ae65bbada0/pkg/proxy/topology.go#L61
					state = loadbalancer.BackendStateActive
				case be.Conditions.IsTerminating() && !be.Conditions.IsServing():
					// A backend that is terminating and not serving should not be used for load-balancing
					// even if it's the only backend. A terminating backend is kept in the BPF maps until
					// fully removed to avoid disrupting connections.
					state = loadbalancer.BackendStateTerminatingNotServing
				case be.Conditions.IsTerminating():
					// A backend that is terminating and serving can still be used for new connections
					// when no active backends are available. A terminating backend is kept in the BPF maps until
					// fully removed to avoid disrupting connections.
					state = loadbalancer.BackendStateTerminating
				default:
					// In all other cases we mark the backend to be in maintenance. This avoids disruptions
					// to existing connections when a backend readiness is flapping.
					state = loadbalancer.BackendStateMaintenance
				}
				weight := be.Weight
				if weight == 0 && !be.Maintenance {
					weight = loadbalancer.DefaultBackendWeight
				}
				bep := loadbalancer.Backend{
					Address:   l3n4Addr,
					NodeName:  be.NodeName,
					PortNames: portNames,
					Weight:    weight,
					State:     state,
				}
				if be.Zone != "" {
					bep.Zone = &loadbalancer.BackendZone{
						Zone:     be.Zone,
						ForZones: be.HintsForZones,
					}
				}
				if !yield(bep) {
					break
				}
			}
		}
	}
}
