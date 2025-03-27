// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

// This includes some utilities for simulating policy verdicts.
//
// It is only used for tests, but is used by multiple packages.

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/u8proto"
)

type Flow struct {
	From, To *identity.Identity
	Proto    u8proto.U8proto
	Dport    uint16
}

type EndpointInfo struct {
	ID uint64

	TCPNamedPorts map[string]uint16
	UDPNamedPorts map[string]uint16

	Logger *slog.Logger

	// Used when determining peer named ports
	remoteEndpoint *EndpointInfo
}

// LookupFlow determines the policy verdict for a given flow.
//
// The flow's identities must have been loaded in to the repository's SelectorCache,
// or policy will not be correctly computed.
//
// This function is only used for testing, but in multiple packages.
//
// TODO: add support for redirects
func LookupFlow(logger *slog.Logger, repo PolicyRepository, flow Flow, srcEP, dstEP *EndpointInfo) (api.Decision, error) {
	if flow.From.ID == 0 || flow.To.ID == 0 {
		return api.Undecided, fmt.Errorf("cannot lookup flow: numeric IDs missing")
	}
	if _, exists := repo.GetSelectorCache().idCache[flow.From.ID]; !exists {
		return api.Undecided, fmt.Errorf("From.ID not in SelectorCache!")
	}
	if _, exists := repo.GetSelectorCache().idCache[flow.To.ID]; !exists {
		return api.Undecided, fmt.Errorf("To.ID not in SelectorCache!")
	}
	if flow.Dport == 0 {
		return api.Undecided, fmt.Errorf("cannot lookup flow: port number missing")
	}
	if flow.Proto == 0 {
		return api.Undecided, fmt.Errorf("cannot lookup flow: protocol missing")
	}

	if srcEP == nil {
		srcEP = &EndpointInfo{
			ID: uint64(flow.From.ID),
		}
	}

	if dstEP == nil {
		dstEP = &EndpointInfo{
			ID: uint64(flow.To.ID),
		}
	}

	srcEP.remoteEndpoint = dstEP
	dstEP.remoteEndpoint = srcEP

	// Resolve and look up the flow as egress from the source
	selPolSrc, _, err := repo.GetSelectorPolicy(flow.From, 0, &dummyPolicyStats{}, srcEP.ID)
	if err != nil {
		return api.Undecided, fmt.Errorf("GetSelectorPolicy(from) failed: %w", err)
	}

	epp := selPolSrc.DistillPolicy(logger, srcEP, nil)
	epp.Ready()
	epp.Detach(logger)
	key := EgressKey().WithIdentity(flow.To.ID).WithPortProto(flow.Proto, flow.Dport)
	entry, _, _ := epp.Lookup(key)
	if entry.IsDeny() {
		return api.Denied, nil
	}

	// Resolve ingress policy for destination
	selPolDst, _, err := repo.GetSelectorPolicy(flow.To, 0, &dummyPolicyStats{}, dstEP.ID)
	if err != nil {
		return api.Undecided, fmt.Errorf("GetSelectorPolicy(to) failed: %w", err)
	}
	epp = selPolDst.DistillPolicy(logger, dstEP, nil)
	epp.Ready()
	epp.Detach(logger)
	key = IngressKey().WithIdentity(flow.From.ID).WithPortProto(flow.Proto, flow.Dport)
	entry, _, _ = epp.Lookup(key)
	if entry.IsDeny() {
		return api.Denied, nil
	}

	return api.Allowed, nil
}

var _ PolicyOwner = &EndpointInfo{}

func (ei *EndpointInfo) GetID() uint64 {
	return ei.ID
}

// GetNamedPort determines the named port of the *destination*. So, if ingress
// is false, then this looks up the peer.
func (ei *EndpointInfo) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	if !ingress && ei.remoteEndpoint != nil {
		return ei.remoteEndpoint.GetNamedPort(true, name, proto)
	}
	switch {
	case proto == u8proto.TCP && ei.TCPNamedPorts != nil:
		return ei.TCPNamedPorts[name]
	case proto == u8proto.UDP && ei.UDPNamedPorts != nil:
		return ei.UDPNamedPorts[name]
	}

	return 0
}

func (ei *EndpointInfo) PolicyDebug(msg string, attrs ...any) {
	if ei.Logger != nil {
		ei.Logger.Debug(msg, attrs...)
	}
}

func (ei *EndpointInfo) IsHost() bool {
	return false
}

// MapStateSize returns the size of the current desired policy map, used for preallocation of the
// new map. Return 0 here as this is only used for testing.
func (ei *EndpointInfo) MapStateSize() int {
	return 0
}

// RegenerateIfAlive returns immediately as there is nothing to regenerate
func (ei *EndpointInfo) RegenerateIfAlive(_ *regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

type dummyPolicyStats struct {
	waitingForPolicyRepository spanstat.SpanStat
	policyCalculation          spanstat.SpanStat
}

func (s *dummyPolicyStats) WaitingForPolicyRepository() *spanstat.SpanStat {
	return &s.waitingForPolicyRepository
}

func (s *dummyPolicyStats) SelectorPolicyCalculation() *spanstat.SpanStat {
	return &s.policyCalculation
}
