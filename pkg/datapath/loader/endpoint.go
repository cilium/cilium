// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func init() {
	epConfigs.register(config.Endpoint)
	epRenames.register(defaultEndpointMapRenames)
}

const (
	symbolFromEndpoint = "cil_from_container"
	symbolToEndpoint   = "cil_to_container"
)

// epConfigs holds functions that yield a BPF configuration object for
// an endpoint.
var epConfigs funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration) any]

// epRenames holds functions that yield the map renames for an endpoint
var epRenames funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration) map[string]string]

// endpointConfiguration returns a slice of endpoint configuration objects
// yielded by all registered config providers.
func endpointConfiguration(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) (configs []any) {
	for f := range epConfigs.all() {
		configs = append(configs, f(ep, lnc))
	}
	return configs
}

// endpointMapRenames returns the merged map of endpoint map renames yielded by all registered rename providers.
func endpointMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) (renames []map[string]string) {
	for f := range epRenames.all() {
		renames = append(renames, f(ep, lnc))
	}
	return renames
}

// ReloadDatapath reloads the BPF datapath programs for the specified endpoint.
//
// It attempts to find a pre-compiled
// template datapath object to use, to avoid a costly compile operation.
// Only if there is no existing template that has the same configuration
// parameters as the specified endpoint, this function will compile a new
// template for this configuration.
//
// This function will block if the cache does not contain an entry for the
// same EndpointConfiguration and multiple goroutines attempt to concurrently
// CompileOrLoad with the same configuration parameters. When the first
// goroutine completes compilation of the template, all other CompileOrLoad
// invocations will be released.
func (l *loader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, stats *metrics.SpanStat) (string, error) {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}

	spec, hash, err := l.templateCache.fetchOrCompile(ctx, lnc, ep, &dirs, stats)
	if err != nil {
		return "", err
	}

	if ep.IsHost() {
		// Reload bpf programs on cilium_host and cilium_net.
		stats.BpfLoadProg.Start()
		err = reloadHostEndpoint(l.logger, ep, lnc, spec)
		stats.BpfLoadProg.End(err == nil)

		l.hostDpInitializedOnce.Do(func() {
			l.logger.Debug("Initialized host datapath")
			close(l.hostDpInitialized)
		})

		return hash, err
	}

	// Reload an lxc endpoint program.
	stats.BpfLoadProg.Start()
	err = reloadEndpoint(l.logger, l.db, l.devices, l.routeManager, ep, lnc, spec)
	stats.BpfLoadProg.End(err == nil)
	return hash, err
}

// Unload removes the datapath specific program aspects
func (l *loader) Unload(ep datapath.Endpoint) {
	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsValid() {
			removeEndpointRoute(ep, l.routeManager)
		}

		if ip := ep.IPv6Address(); ip.IsValid() {
			removeEndpointRoute(ep, l.routeManager)
		}
	}

	log := l.logger.With(logfields.EndpointID, ep.StringID())

	// Remove legacy tc attachments.
	link, err := safenetlink.LinkByName(ep.InterfaceName())
	if err == nil {
		if err := removeTCFilters(link, netlink.HANDLE_MIN_INGRESS); err != nil {
			log.Error(
				"Failed to remove ingress filter from interface",
				logfields.Error, err,
				logfields.Interface, ep.InterfaceName(),
			)
		}
		if err := removeTCFilters(link, netlink.HANDLE_MIN_EGRESS); err != nil {
			log.Error(
				"Failed to remove egress filter from interface",
				logfields.Error, err,
				logfields.Interface, ep.InterfaceName(),
			)
		}
	}

	// If Cilium and the kernel support tcx to attach TC programs to the
	// endpoint's veth device, its bpf_link object is pinned to a per-endpoint
	// bpffs directory. When the endpoint gets deleted, we can remove the whole
	// directory to clean up any leftover pinned links and maps.

	// Remove the links directory first to avoid removing program arrays before
	// the entrypoints are detached.
	if err := bpf.Remove(bpffsEndpointLinksDir(bpf.CiliumPath(), ep)); err != nil {
		log.Error("Failed to remove bpffs entry",
			logfields.Error, err,
			logfields.BPFFSEndpointLinksDir, bpffsEndpointLinksDir(bpf.CiliumPath(), ep),
		)
	}
	// Finally, remove the endpoint's top-level directory.
	if err := bpf.Remove(bpffsEndpointDir(bpf.CiliumPath(), ep)); err != nil {
		log.Error("Failed to remove bpffs entry",
			logfields.Error, err,
			logfields.BPFFSEndpointDir, bpffsEndpointDir(bpf.CiliumPath(), ep),
		)
	}
}

// EndpointHash hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func (l *loader) EndpointHash(cfg datapath.EndpointConfiguration, lnCfg *datapath.LocalNodeConfiguration) (string, error) {
	return l.templateCache.baseHash.hashEndpoint(l.templateCache, lnCfg, cfg)
}

func (l *loader) WriteEndpointConfig(w io.Writer, e datapath.EndpointConfiguration, lnCfg *datapath.LocalNodeConfiguration) error {
	return l.configWriter.WriteEndpointConfig(w, lnCfg, e)
}

// defaultEndpointMapRenames returns map rename operations for an endpoint.
func defaultEndpointMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) map[string]string {
	return map[string]string{
		// Rename the calls and policy maps to include the endpoint's id.
		"cilium_calls":     bpf.LocalMapName(callsmap.MapName, uint16(ep.GetID())),
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}
}

// reloadEndpoint loads programs in spec into the device used by ep.
//
// spec is modified by the method and it is the callers responsibility to copy
// it if necessary.
func reloadEndpoint(logger *slog.Logger, db *statedb.DB,
	devices statedb.Table[*tables.Device], rm *routeReconciler.DesiredRouteManager,
	ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {

	var obj lxcObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:      endpointConfiguration(ep, lnc),
		MapRenames:     endpointMapRenames(ep, lnc),
		ConfigDumpPath: filepath.Join(ep.StateDir(), endpointConfig),
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	// Insert policy programs before attaching entrypoints to tc hooks.
	// Inserting a policy program is considered an attachment, since it makes
	// the code reachable by bpf_host when it evaluates policy for the endpoint.
	// All internal tail call plumbing needs to be done before this point.
	// If the agent dies uncleanly after the first program has been inserted,
	// the endpoint's connectivity will be partially broken or exhibit undefined
	// behaviour like missed tail calls or drops.
	if err := obj.PolicyMap.Update(uint32(ep.GetID()), obj.PolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting endpoint policy program: %w", err)
	}
	if err := obj.EgressPolicyMap.Update(uint32(ep.GetID()), obj.EgressPolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting endpoint egress policy program: %w", err)
	}

	device := ep.InterfaceName()
	iface, err := safenetlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", device, err)
	}

	linkDir := bpffsEndpointLinksDir(bpf.CiliumPath(), ep)
	if err := attachSKBProgram(logger, iface, obj.FromContainer, symbolFromEndpoint,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}

	if ep.RequireEgressProg() {
		if err := attachSKBProgram(logger, iface, obj.ToContainer, symbolToEndpoint,
			linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s egress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, iface, symbolToEndpoint, linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
			logger.Error(
				"",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsValid() {
			if err := upsertEndpointRoute(db, devices, rm, ep, netip.PrefixFrom(ip, ip.BitLen())); err != nil {
				return fmt.Errorf("upserting IPv4 route for endpoint %s: %w", ep.StringID(), err)
			}
		}
		if ip := ep.IPv6Address(); ip.IsValid() {
			if err := upsertEndpointRoute(db, devices, rm, ep, netip.PrefixFrom(ip, ip.BitLen())); err != nil {
				return fmt.Errorf("upserting IPv6 route for endpoint %s: %w", ep.StringID(), err)
			}
		}
	}

	return nil
}

func registerRouteInitializer(p Params) {
	// [upsertEndpointRoute] Creates routes for endpoints that need per endpoint routes.
	// We need to tell the route reconciler to delay pruning of routes from the kernel until we have had a chance
	// to insert desired routes for all endpoints that need them.
	//
	// Use the endpoint restorer to get a signal when all existing endpoints have been restored, and thus
	// [loader.ReloadDatapath] has been called for all existing endpoints. After that we can finalize the route
	// initializer.
	routeInitializer := p.RouteManager.RegisterInitializer("per-endpoint-routes")
	p.JobGroup.Add(job.OneShot("per-endpoint-route-initializer", func(ctx context.Context, _ cell.Health) error {
		defer p.RouteManager.FinalizeInitializer(routeInitializer)

		epRestorer, err := p.EPRestorer.Await(ctx)
		if err != nil {
			return fmt.Errorf("waiting for endpoint restorer: %w", err)
		}

		if err := epRestorer.WaitForEndpointRestore(ctx); err != nil {
			return fmt.Errorf("waiting for endpoint restore: %w", err)
		}

		return nil
	}))
}

func upsertEndpointRoute(db *statedb.DB, devices statedb.Table[*tables.Device], rm *routeReconciler.DesiredRouteManager, ep datapath.Endpoint, ip netip.Prefix) error {
	owner, err := rm.GetOrRegisterOwner("endpoint/" + ep.StringID())
	if err != nil {
		return fmt.Errorf("getting or registering owner for endpoint %s: %w", ep.StringID(), err)
	}

	// This timeout is 50 times the current batch interval of the devices controller, and thus should
	// be sufficient.
	const devTableWaitTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), devTableWaitTimeout)
	defer cancel()

	// Find the device associated with the endpoint. Up to this point we have only got the ifindex
	// and the table may not yet have been populated with devices. Wait for the device to appear.
	var epDev *tables.Device
	for {
		var found bool
		var watch <-chan struct{}
		epDev, _, watch, found = devices.GetWatch(db.ReadTxn(), tables.DeviceIDIndex.Query(ep.GetIfIndex()))
		if found {
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("device %d not found for endpoint %s: %w", ep.GetIfIndex(), ep.StringID(), ctx.Err())
		case <-watch:
		}
	}

	return rm.UpsertRoute(routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        ip,
		Table:         routeReconciler.TableMain,
		AdminDistance: routeReconciler.AdminDistanceDefault,

		Device: epDev,
		Scope:  routeReconciler.SCOPE_LINK,
	})
}

func removeEndpointRoute(ep datapath.Endpoint, rm *routeReconciler.DesiredRouteManager) error {
	owner, err := rm.GetOwner("endpoint/" + ep.StringID())
	if err != nil {
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}

		return fmt.Errorf("getting route owner for endpoint %s: %w", ep.StringID(), err)
	}

	return rm.RemoveOwner(owner)
}
