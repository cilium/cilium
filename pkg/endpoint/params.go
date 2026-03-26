// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	loader "github.com/cilium/cilium/pkg/datapath/loader/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"

	"github.com/cilium/hive/cell"
)

// EndpointParams is used to pass the many dependencies required
// to create an endpoint.
type EndpointParams struct {
	cell.In

	Logger              *slog.Logger
	EPBuildQueue        EndpointBuildQueue
	Loader              loader.Loader
	Orchestrator        endpoint.Orchestrator
	CompilationLock     loader.CompilationLock
	BandwidthManager    bandwidth.Manager
	IPTablesManager     iptables.Manager
	IdentityManager     identitymanager.IDManager
	MonitorAgent        monitoragent.Agent
	PolicyMapFactory    policymap.Factory
	PolicyRepo          policy.PolicyRepository
	Allocator           cache.IdentityAllocator
	CTMapGC             ctmap.GCRunner
	KVStoreSynchronizer *ipcache.IPIdentitySynchronizer
	WgConfig            wgTypes.WireguardConfig
	IPSecConfig         datapath.IPsecConfig
	NamedPortsGetter    NamedPortsGetter
	LxcMap              lxcmap.Map
	LocalNodeStore      node.NodeGetter
}
