// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	symbolFromNetwork = "cil_from_network"

	dirIngress = "ingress"
	dirEgress  = "egress"
)

// loader is a wrapper structure around operations related to compiling,
// loading, and reloading datapath programs.
type loader struct {
	logger *slog.Logger

	// templateCache is the cache of pre-compiled datapaths. Only set after
	// a call to Reinitialize.
	templateCache *objectCache

	ipsecMu lock.Mutex // guards reinitializeIPSec

	hostDpInitializedOnce sync.Once
	hostDpInitialized     chan struct{}

	sysctl             sysctl.Sysctl
	prefilter          datapath.PreFilter
	compilationLock    datapath.CompilationLock
	configWriter       datapath.ConfigWriter
	nodeConfigNotifier *manager.NodeConfigNotifier

	db           *statedb.DB
	devices      statedb.Table[*tables.Device]
	routeManager *routeReconciler.DesiredRouteManager
}

type Params struct {
	cell.In

	JobGroup           job.Group
	Logger             *slog.Logger
	Sysctl             sysctl.Sysctl
	Prefilter          datapath.PreFilter
	CompilationLock    datapath.CompilationLock
	ConfigWriter       datapath.ConfigWriter
	NodeConfigNotifier *manager.NodeConfigNotifier
	RouteManager       *routeReconciler.DesiredRouteManager
	DB                 *statedb.DB
	Devices            statedb.Table[*tables.Device]
	EPRestorer         promise.Promise[endpointstate.Restorer]
	BIGTCPConfig       *bigtcp.Configuration

	// Force map initialisation before loader. You should not use these otherwise.
	// Some of the entries in this slice may be nil.
	BpfMaps []bpf.BpfMap `group:"bpf-maps"`
}

// newLoader returns a new loader.
func newLoader(p Params) *loader {
	registerRouteInitializer(p)
	return &loader{
		logger:             p.Logger,
		templateCache:      newObjectCache(p.Logger, p.ConfigWriter, filepath.Join(option.Config.StateDir, defaults.TemplatesDir)),
		sysctl:             p.Sysctl,
		hostDpInitialized:  make(chan struct{}),
		prefilter:          p.Prefilter,
		compilationLock:    p.CompilationLock,
		configWriter:       p.ConfigWriter,
		nodeConfigNotifier: p.NodeConfigNotifier,
		routeManager:       p.RouteManager,

		db:      p.DB,
		devices: p.Devices,
	}
}

// CallsMapPath gets the BPF Calls Map for the endpoint with the specified ID.
func (l *loader) CallsMapPath(id uint16) string {
	return bpf.LocalMapPath(l.logger, callsmap.MapName, id)
}

// HostDatapathInitialized returns a channel which is closed when the
// host datapath has been loaded for the first time.
func (l *loader) HostDatapathInitialized() <-chan struct{} {
	return l.hostDpInitialized
}
