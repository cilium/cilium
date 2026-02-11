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
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/u8proto"
)

type endpointInfo struct {
	ID uint64

	TCPNamedPorts map[string]uint16
	UDPNamedPorts map[string]uint16

	Logger *slog.Logger

	// Used when determining peer named ports
	remoteEndpoint *endpointInfo
}

// LookupFlow determines the policy verdict for a given flow.
//
// The flow's identities must have been loaded in to the repository's SelectorCache,
// or policy will not be correctly computed.
//
// This function is only used for testing, but in multiple packages.
//
// TODO: add support for redirects
func LookupFlow(logger *slog.Logger, repo PolicyRepository, identityManager identitymanager.IDManager, flow types.Flow) (verdict types.LookupResult, egress, ingress RuleMeta, err error) {
	identityManager.Add(flow.From)
	identityManager.Add(flow.To)
	defer func() {
		identityManager.Remove(flow.From)
		identityManager.Remove(flow.To)
	}()

	if flow.From.ID == 0 || flow.To.ID == 0 {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("cannot lookup flow: numeric IDs missing")
	}
	if !repo.GetSubjectSelectorCache().idCache.exists(flow.From.ID) {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("From.ID not in SelectorCache!")
	}
	if !repo.GetSubjectSelectorCache().idCache.exists(flow.To.ID) {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("To.ID not in SelectorCache!")
	}
	if flow.Dport == 0 {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("cannot lookup flow: port number missing")
	}
	if flow.Proto == 0 {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("cannot lookup flow: protocol missing")
	}

	srcEP := &endpointInfo{
		ID:            uint64(flow.From.ID),
		TCPNamedPorts: flow.NamedPortsTCP,
		UDPNamedPorts: flow.NamedPortsUDP,
	}
	dstEP := &endpointInfo{
		ID:            uint64(flow.To.ID),
		TCPNamedPorts: flow.NamedPortsTCP,
		UDPNamedPorts: flow.NamedPortsUDP,
	}
	srcEP.remoteEndpoint = dstEP
	dstEP.remoteEndpoint = srcEP

	// Resolve and look up the flow as egress from the source
	selPolSrc, _, err := repo.GetSelectorPolicy(flow.From, 0, &dummyPolicyStats{}, srcEP.ID)
	if err != nil {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("GetSelectorPolicy(from) failed: %w", err)
	}

	epp := selPolSrc.DistillPolicy(logger, srcEP, nil)
	epp.Ready()
	epp.Detach(logger)
	key := EgressKey().WithIdentity(flow.To.ID).WithPortProto(flow.Proto, flow.Dport)
	egressEntry, ingress, _ := epp.Lookup(key)
	if egressEntry.IsDeny() {
		verdict.Egress = types.DecisionDenied
	} else {
		verdict.Egress = types.DecisionAllowed
	}

	// Resolve ingress policy for destination
	selPolDst, _, err := repo.GetSelectorPolicy(flow.To, 0, &dummyPolicyStats{}, dstEP.ID)
	if err != nil {
		return types.LookupResult{}, ingress, egress, fmt.Errorf("GetSelectorPolicy(to) failed: %w", err)
	}
	epp = selPolDst.DistillPolicy(logger, dstEP, nil)
	epp.Ready()
	epp.Detach(logger)
	key = IngressKey().WithIdentity(flow.From.ID).WithPortProto(flow.Proto, flow.Dport)
	ingressEntry, egress, _ := epp.Lookup(key)
	if ingressEntry.IsDeny() {
		verdict.Ingress = types.DecisionDenied
	} else {
		verdict.Ingress = types.DecisionAllowed
	}

	return verdict, ingress, egress, nil
}

var _ PolicyOwner = &endpointInfo{}

func (ei *endpointInfo) GetID() uint64 {
	return ei.ID
}

// GetNamedPort determines the named port of the *destination*. So, if ingress
// is false, then this looks up the peer.
func (ei *endpointInfo) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
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

func (ei *endpointInfo) PolicyDebug(msg string, attrs ...any) {
	if ei.Logger != nil {
		ei.Logger.Debug(msg, attrs...)
	}
}

func (ei *endpointInfo) IsHost() bool {
	return false
}

// PreviousMapState returns an empty mapstate
func (ei *endpointInfo) PreviousMapState() *MapState {
	return nil
}

// RegenerateIfAlive returns immediately as there is nothing to regenerate
func (ei *endpointInfo) RegenerateIfAlive(*regeneration.ExternalRegenerationMetadata) <-chan bool {
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
