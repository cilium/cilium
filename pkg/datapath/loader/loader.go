// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	subsystem = "datapath-loader"

	symbolFromNetwork = "cil_from_network"

	symbolToWireguard   = "cil_to_wireguard"
	symbolFromWireguard = "cil_from_wireguard"

	symbolFromHostNetdevXDP = "cil_xdp_entry"

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

func replaceWireguardDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, device netlink.Link) (err error) {
	if err := compileWireguard(ctx, logger); err != nil {
		return fmt.Errorf("compiling wireguard program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(wireguardObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", wireguardObj, err)
	}

	cfg := config.NewBPFWireguard(config.NodeConfig(lnc))
	cfg.InterfaceIfIndex = uint32(device.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2
	cfg.EphemeralMin = lnc.EphemeralMin

	var obj wireguardObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: cfg,
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_wireguard_%d", device.Attrs().Index),
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), device)
	// Attach/detach cil_to_wireguard to/from egress.
	if option.Config.NeedEgressOnWireGuardDevice(lnc.KPRConfig, lnc.EnableWireguard) {
		if err := attachSKBProgram(logger, device, obj.ToWireguard, symbolToWireguard,
			linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s egress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, device, symbolToWireguard,
			linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
			logger.Error("",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}
	// Attach/detach cil_from_wireguard to/from ingress.
	if option.Config.NeedIngressOnWireGuardDevice(lnc.KPRConfig, lnc.EnableWireguard) {
		if err := attachSKBProgram(logger, device, obj.FromWireguard, symbolFromWireguard,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s ingress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, device, symbolFromWireguard,
			linkDir, netlink.HANDLE_MIN_INGRESS); err != nil {
			logger.Error("",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}
	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}
	return nil
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
