// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
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
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/time"
)

var launchTime = 30 * time.Second

type EndpointCreator interface {
	// NewEndpointFromChangeModel creates a new endpoint from a request
	NewEndpointFromChangeModel(ctx context.Context, base *models.EndpointChangeRequest) (*endpoint.Endpoint, error)

	ParseEndpoint(epJSON []byte) (*endpoint.Endpoint, error)

	// AddIngressEndpoint creates an Endpoint representing Cilium Ingress on this node without a
	// corresponding container necessarily existing. This is needed to be able to ingest and
	// sync network policies applicable to Cilium Ingress to Envoy.
	AddIngressEndpoint(ctx context.Context) error

	AddHostEndpoint(ctx context.Context) error
}

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
	// kvstoreSyncher updates the kvstore (e.g., etcd) with up-to-date
	// information about endpoints.
	kvstoreSyncher *ipcache.IPIdentitySynchronizer
}

var _ EndpointCreator = &endpointCreator{}

type endpointManagerParams struct {
	cell.In

	EndpointManager     endpointmanager.EndpointManager
	DNSRulesService     fqdnrules.DNSRulesService
	EPBuildQueue        endpoint.EndpointBuildQueue
	Loader              datapath.Loader
	Orchestrator        datapath.Orchestrator
	CompilationLock     datapath.CompilationLock
	BandwidthManager    datapath.BandwidthManager
	IPTablesManager     datapath.IptablesManager
	IdentityManager     identitymanager.IDManager
	MonitorAgent        monitoragent.Agent
	PolicyMapFactory    policymap.Factory
	PolicyRepo          policy.PolicyRepository
	IPCache             *ipcache.IPCache
	Proxy               *proxy.Proxy
	Allocator           cache.IdentityAllocator
	CTMapGC             ctmap.GCRunner
	KVStoreSynchronizer *ipcache.IPIdentitySynchronizer
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
		kvstoreSyncher:   p.KVStoreSynchronizer,
	}
}

func (c *endpointCreator) NewEndpointFromChangeModel(ctx context.Context, base *models.EndpointChangeRequest) (*endpoint.Endpoint, error) {
	return endpoint.NewEndpointFromChangeModel(
		ctx,
		c.dnsRulesAPI,
		c.epBuildQueue,
		c.loader,
		c.orchestrator,
		c.compilationLock,
		c.bandwidthManager,
		c.ipTablesManager,
		c.identityManager,
		c.monitorAgent,
		c.policyMapFactory,
		c.policyRepo,
		c.ipcache,
		c.proxy,
		c.allocator,
		c.ctMapGC,
		c.kvstoreSyncher,
		base,
	)
}

func (c *endpointCreator) ParseEndpoint(epJSON []byte) (*endpoint.Endpoint, error) {
	return endpoint.ParseEndpoint(
		c.dnsRulesAPI,
		c.epBuildQueue,
		c.loader,
		c.orchestrator,
		c.compilationLock,
		c.bandwidthManager,
		c.ipTablesManager,
		c.identityManager,
		c.monitorAgent,
		c.policyMapFactory,
		c.policyRepo,
		c.ipcache,
		c.proxy,
		c.allocator,
		c.ctMapGC,
		c.kvstoreSyncher,
		epJSON,
	)
}

func (c *endpointCreator) AddIngressEndpoint(ctx context.Context) error {
	ep, err := endpoint.CreateIngressEndpoint(
		c.dnsRulesAPI,
		c.epBuildQueue,
		c.loader,
		c.orchestrator,
		c.compilationLock,
		c.bandwidthManager,
		c.ipTablesManager,
		c.identityManager,
		c.monitorAgent,
		c.policyMapFactory,
		c.policyRepo,
		c.ipcache,
		c.proxy,
		c.allocator,
		c.ctMapGC,
		c.kvstoreSyncher,
	)
	if err != nil {
		return err
	}

	if err := c.endpointManager.AddEndpoint(ep); err != nil {
		return err
	}

	ep.InitWithIngressLabels(ctx, launchTime)

	return nil
}

func (c *endpointCreator) AddHostEndpoint(ctx context.Context) error {
	ep, err := endpoint.CreateHostEndpoint(
		c.dnsRulesAPI,
		c.epBuildQueue,
		c.loader,
		c.orchestrator,
		c.compilationLock,
		c.bandwidthManager,
		c.ipTablesManager,
		c.identityManager,
		c.monitorAgent,
		c.policyMapFactory,
		c.policyRepo,
		c.ipcache,
		c.proxy,
		c.allocator,
		c.ctMapGC,
		c.kvstoreSyncher,
	)
	if err != nil {
		return err
	}

	if err := c.endpointManager.AddEndpoint(ep); err != nil {
		return err
	}

	node.SetEndpointID(ep.GetID())

	c.endpointManager.InitHostEndpointLabels(ctx)

	return nil
}
