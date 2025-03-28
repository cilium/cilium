// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"github.com/cilium/hive/cell"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	fqdnrules "github.com/cilium/cilium/pkg/fqdn/rules"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
)

type EndpointCreator interface{}

type endpointCreator struct {
	endpointManager  endpointmanager.EndpointManager
	dnsRulesAPI      fqdnrules.DNSRulesService
	epBuildQueue     endpoint.EndpointBuildQueue
	loader           datapath.Loader
	orchestrator     datapath.Orchestrator
	compilationLock  datapath.CompilationLock
	bandwidthManager datapath.BandwidthManager
	ipTablesManager  datapath.IptablesManager
	identityManager  identitymanager.IDManager
	monitorAgent     monitoragent.Agent
	policyMapFactory policymap.Factory
	policyRepo       policy.PolicyRepository
	ipcache          *ipcache.IPCache
	proxy            endpoint.EndpointProxy
	allocator        cache.IdentityAllocator
	ctMapGC          ctmap.GCRunner
}

var _ EndpointCreator = &endpointCreator{}

type endpointManagerParams struct {
	cell.In

	EndpointManager  endpointmanager.EndpointManager
	DNSRulesService  fqdnrules.DNSRulesService
	EPBuildQueue     endpoint.EndpointBuildQueue
	Loader           datapath.Loader
	Orchestrator     datapath.Orchestrator
	CompilationLock  datapath.CompilationLock
	BandwidthManager datapath.BandwidthManager
	IPTablesManager  datapath.IptablesManager
	IdentityManager  identitymanager.IDManager
	MonitorAgent     monitoragent.Agent
	PolicyMapFactory policymap.Factory
	PolicyRepo       policy.PolicyRepository
	IPCache          *ipcache.IPCache
	Proxy            *proxy.Proxy
	Allocator        cache.IdentityAllocator
	CTMapGC          ctmap.GCRunner
}

func newEndpointCreator(p endpointManagerParams) EndpointCreator {
	return &endpointCreator{
		endpointManager:  p.EndpointManager,
		dnsRulesAPI:      p.DNSRulesService,
		epBuildQueue:     p.EPBuildQueue,
		loader:           p.Loader,
		orchestrator:     p.Orchestrator,
		compilationLock:  p.CompilationLock,
		bandwidthManager: p.BandwidthManager,
		ipTablesManager:  p.IPTablesManager,
		identityManager:  p.IdentityManager,
		monitorAgent:     p.MonitorAgent,
		policyMapFactory: p.PolicyMapFactory,
		policyRepo:       p.PolicyRepo,
		ipcache:          p.IPCache,
		proxy:            p.Proxy,
		allocator:        p.Allocator,
		ctMapGC:          p.CTMapGC,
	}
}
