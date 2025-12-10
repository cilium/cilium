// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cell

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/parser"
	hubbleGetters "github.com/cilium/cilium/pkg/hubble/parser/getters"
	parserOptions "github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

var Cell = cell.Module(
	"payload-parser",
	"Provides a payload parser for Hubble",

	cell.Provide(newPayloadParser),
	cell.Config(defaultConfig),
)

func newPayloadParser(params payloadParserParams) (parser.Decoder, error) {
	if err := params.Config.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}
	g := &payloadGetters{
		log:               params.Log,
		db:                params.DB,
		frontends:         params.Frontends,
		identityAllocator: params.IdentityAllocator,
		endpointManager:   params.EndpointManager,
		ipcache:           params.Ipcache,
	}
	var parserOpts []parserOptions.Option
	if params.Config.EnableRedact {
		parserOpts = append(
			parserOpts,
			parserOptions.WithRedact(
				params.Config.RedactHttpURLQuery,
				params.Config.RedactHttpUserInfo,
				params.Config.RedactKafkaAPIKey,
				params.Config.RedactHttpHeadersAllow,
				params.Config.RedactHttpHeadersDeny,
			),
		)
	}
	parserOpts = append(
		parserOpts,
		parserOptions.WithNetworkPolicyCorrelation(
			params.Config.EnableNetworkPolicyCorrelation,
		))
	parserOpts = append(
		parserOpts,
		parserOptions.WithSkipUnknownCGroupIDs(
			params.Config.SkipUnknownCGroupIDs,
		),
	)
	parserOpts = append(
		parserOpts,
		params.ParserOptions...,
	)
	return parser.New(params.Log, g, g, g, params.Ipcache, g, params.LinkCache, params.CGroupManager, parserOpts...)
}

type payloadParserParams struct {
	cell.In

	Log *slog.Logger

	DB                *statedb.DB
	Frontends         statedb.Table[*loadbalancer.Frontend]
	IdentityAllocator identitycell.CachingIdentityAllocator
	EndpointManager   endpointmanager.EndpointManager
	Ipcache           *ipcache.IPCache
	CGroupManager     manager.CGroupManager
	LinkCache         *link.LinkCache

	Config config
	// NOTE: ordering is not guaranteed, do not rely on it.
	ParserOptions []parserOptions.Option `group:"hubble-parser-options"`
}

type payloadGetters struct {
	log *slog.Logger

	identityAllocator identitycell.CachingIdentityAllocator
	endpointManager   endpointmanager.EndpointManager
	ipcache           *ipcache.IPCache
	db                *statedb.DB
	frontends         statedb.Table[*loadbalancer.Frontend]
}

// GetIdentity implements IdentityGetter. It looks up identity by ID from
// Cilium's identity cache. Hubble uses the identity info to populate flow
// source and destination labels.
func (p *payloadGetters) GetIdentity(securityIdentity uint32) (*identity.Identity, error) {
	ident := p.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident, nil
}

// GetEndpointInfo implements EndpointGetter. It returns endpoint info for a
// given IP address. Hubble uses this function to populate fields like
// namespace and pod name for local endpoints.
func (h *payloadGetters) GetEndpointInfo(ip netip.Addr) (endpoint hubbleGetters.EndpointInfo, ok bool) {
	if !ip.IsValid() {
		return nil, false
	}
	ep := h.endpointManager.LookupIP(ip)
	if ep == nil {
		return nil, false
	}
	return ep, true
}

// GetEndpointInfoByID implements EndpointGetter. It returns endpoint info for
// a given Cilium endpoint id. Used by Hubble.
func (h *payloadGetters) GetEndpointInfoByID(id uint16) (endpoint hubbleGetters.EndpointInfo, ok bool) {
	ep := h.endpointManager.LookupCiliumID(id)
	if ep == nil {
		return nil, false
	}
	return ep, true
}

// GetNamesOf implements DNSGetter.GetNamesOf. It looks up DNS names of a given
// IP from the FQDN cache of an endpoint specified by sourceEpID.
func (h *payloadGetters) GetNamesOf(sourceEpID uint32, ip netip.Addr) []string {
	ep := h.endpointManager.LookupCiliumID(uint16(sourceEpID))
	if ep == nil {
		return nil
	}

	if !ip.IsValid() {
		return nil
	}
	names := ep.DNSHistory.LookupIP(ip)

	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}

	return names
}

// GetServiceByAddr implements ServiceGetter. It looks up service by IP/port.
// Hubble uses this function to annotate flows with service information.
func (h *payloadGetters) GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service {
	if !ip.IsValid() {
		return nil
	}
	addrCluster := cmtypes.AddrClusterFrom(ip, 0)
	txn := h.db.ReadTxn()
	fe, found := loadbalancer.LookupFrontendByTuple(txn, h.frontends, addrCluster, loadbalancer.TCP, port, loadbalancer.ScopeExternal)
	if !found {
		fe, found = loadbalancer.LookupFrontendByTuple(txn, h.frontends, addrCluster, loadbalancer.UDP, port, loadbalancer.ScopeExternal)
	}
	if !found {
		return nil
	}
	return &flowpb.Service{
		Namespace: fe.ServiceName.Namespace(),
		Name:      fe.ServiceName.Name(),
	}
}
