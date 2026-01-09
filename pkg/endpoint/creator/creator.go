// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/lumberjack/v2"
	"go4.org/netipx"

	"github.com/cilium/cilium/api/v1/models"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	fqdnrules "github.com/cilium/cilium/pkg/fqdn/rules"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/time"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
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
	logger           *slog.Logger
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
	wgConfig       wgTypes.WireguardConfig
	ipsecConfig    datapath.IPsecConfig
	policyLogger   func() *lumberjack.Logger
	lxcMap         lxcmap.Map
	localNodeStore *node.LocalNodeStore
}

var _ EndpointCreator = &endpointCreator{}

type endpointManagerParams struct {
	cell.In

	Logger              *slog.Logger
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
	WgConfig            wgTypes.WireguardConfig
	IPSecConfig         datapath.IPsecConfig
	LXCMap              lxcmap.Map
	LocalNodeStore      *node.LocalNodeStore
}

func newEndpointCreator(p endpointManagerParams) EndpointCreator {
	return &endpointCreator{
		logger:           p.Logger,
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
		wgConfig:         p.WgConfig,
		ipsecConfig:      p.IPSecConfig,
		policyLogger:     sync.OnceValue(policyDebugLogger),
		lxcMap:           p.LXCMap,
		localNodeStore:   p.LocalNodeStore,
	}
}

func policyDebugLogger() *lumberjack.Logger {
	maxSize := 10 // 10 MB
	if ms := os.Getenv("CILIUM_DBG_POLICY_LOG_MAX_SIZE"); ms != "" {
		if ms, err := strconv.Atoi(ms); err == nil {
			maxSize = ms
		}
	}
	maxBackups := 3
	if mb := os.Getenv("CILIUM_DBG_POLICY_LOG_MAX_BACKUPS"); mb != "" {
		if mb, err := strconv.Atoi(mb); err == nil {
			maxBackups = mb
		}
	}
	return &lumberjack.Logger{
		Filename:   filepath.Join(option.Config.StateDir, "endpoint-policy.log"),
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     28, // days
		LocalTime:  true,
		Compress:   true,
	}
}

func (c *endpointCreator) NewEndpointFromChangeModel(ctx context.Context, base *models.EndpointChangeRequest) (*endpoint.Endpoint, error) {
	return endpoint.NewEndpointFromChangeModel(
		ctx,
		c.logger,
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
		c.wgConfig,
		c.ipsecConfig,
		c.policyLogger(),
		c.lxcMap,
		c.localNodeStore,
	)
}

func (c *endpointCreator) ParseEndpoint(epJSON []byte) (*endpoint.Endpoint, error) {
	return endpoint.ParseEndpoint(
		c.logger,
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
		c.wgConfig,
		c.ipsecConfig,
		c.lxcMap,
		c.localNodeStore,
	)
}

func (c *endpointCreator) AddIngressEndpoint(ctx context.Context) error {
	ln, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	// Node.IPv4IngressIP has been parsed with net.ParseIP() and may be in IPv4 mapped IPv6
	// address format. Use netipx.FromStdIP() to make sure we get a plain IPv4 address.
	ingressIPv4, _ := netipx.FromStdIP(ln.IPv4IngressIP)
	ingressIPv6, _ := netip.AddrFromSlice(ln.IPv6IngressIP)

	ep, err := endpoint.CreateIngressEndpoint(
		c.logger,
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
		c.wgConfig,
		c.ipsecConfig,
		c.policyLogger(),
		c.lxcMap,
		c.localNodeStore,
		ingressIPv4,
		ingressIPv6,
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
		c.logger,
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
		c.wgConfig,
		c.ipsecConfig,
		c.policyLogger(),
		c.lxcMap,
		c.localNodeStore,
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
