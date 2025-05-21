// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	healthDefaults "github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type endpointUpdaterParams struct {
	cell.In

	Lifecycle   cell.Lifecycle
	Health      cell.Health
	JobRegistry job.Registry
	DB          *statedb.DB
	MTUTable    statedb.Table[RouteMTU]
	DeviceTable statedb.Table[*tables.Device]
	Logger      *slog.Logger
	MTUConfig   Config
	CNI         cni.CNIConfigManager
}

type EndpointMTUUpdater interface {
	// RegisterHook registers a hook to be called when updating the MTU of endpoints.
	// The hook is called from within the network namespace of each endpoint.
	RegisterHook(hook EndpointMTUUpdateHook)
}

type EndpointMTUUpdateHook func(routeMTUs []RouteMTU) error

func newEndpointUpdater(p endpointUpdaterParams) EndpointMTUUpdater {
	endpointUpdater := endpointUpdater{
		logger:      p.Logger,
		db:          p.DB,
		mtuTable:    p.MTUTable,
		deviceTable: p.DeviceTable,
		hooks:       []EndpointMTUUpdateHook{defaultRouteHook},
	}

	// If chaining mode is enabled
	if p.CNI.GetChainingMode() != "none" {
		EnableRouteMTU := false
		if p.CNI.GetCustomNetConf() != nil {
			EnableRouteMTU = p.CNI.GetCustomNetConf().EnableRouteMTU
		}
		// And the CNI config nor Cilium config requests us to manage route MTU in chaining mode
		// Don't start the endpoint updater
		if !EnableRouteMTU && !p.MTUConfig.EnableRouteMTUForCNIChaining {
			return &endpointUpdater
		}
	}

	// If we are not in chaining mode, or if we are in chaining mode and the CNI config requests us to manage route MTU
	// Start the endpoint updater
	jobGroup := p.JobRegistry.NewGroup(p.Health, p.Lifecycle)
	jobGroup.Add(job.OneShot("endpoint-mtu-updater", endpointUpdater.Updater))

	return &endpointUpdater
}

type endpointUpdater struct {
	logger      *slog.Logger
	db          *statedb.DB
	mtuTable    statedb.Table[RouteMTU]
	deviceTable statedb.Table[*tables.Device]
	hooks       []EndpointMTUUpdateHook
}

func (emu *endpointUpdater) Updater(ctx context.Context, health cell.Health) error {
	var (
		curMTUs []RouteMTU
		watch   <-chan struct{}
		errs    []error
	)

	// Set watch to closed channel to trigger the first iteration.
	closed := make(chan struct{})
	close(closed)
	watch = closed

	retryLimit := backoff.Exponential{
		Logger: emu.logger,
		Name:   "endpoint-mtu-updater",
		Min:    1 * time.Second,
		Max:    1 * time.Minute,
	}

	for {
		// If we had errors last round, wait for the retry limit before trying again.
		if len(errs) != 0 {
			if err := retryLimit.Wait(ctx); err != nil {
				return nil
			}
		} else {
			// If this is the first time, or all went well last round, wait for a change in the MTU table.
			select {
			case <-watch:
			case <-ctx.Done():
				return nil
			}
		}

		rx := emu.db.ReadTxn()

		var mtuIter iter.Seq2[RouteMTU, uint64]
		mtuIter, watch = emu.mtuTable.AllWatch(rx)

		var newMtus []RouteMTU
		for routeMtu := range mtuIter {
			newMtus = append(newMtus, routeMtu)
		}
		slices.SortFunc(newMtus, routeMTUCmp)

		// If the MTUs haven't changed, and there were no errors last round, skip the update.
		if slices.Equal(curMTUs, newMtus) && len(errs) == 0 {
			retryLimit.Reset()
			continue
		}

		errs = errs[:0]

		if err := emu.updateHostNSDevices(rx, newMtus); err != nil {
			errs = append(errs, err)
		}
		if err := emu.updateEndpoints(newMtus); err != nil {
			errs = append(errs, err)
		}
		if err := emu.updateHealthEndpoint(newMtus); err != nil {
			errs = append(errs, err)
		}

		if len(errs) != 0 {
			health.Degraded("Error(s) while updating MTU for endpoints", errors.Join(errs...))
			continue
		}

		health.OK("Endpoint MTU updated")
		curMTUs = newMtus
		retryLimit.Reset()
	}
}

func (emu *endpointUpdater) updateHostNSDevices(rx statedb.ReadTxn, routeMtus []RouteMTU) error {
	defaultRouteMTU, err := defaultRoute(routeMtus)
	if err != nil {
		return err
	}

	// Update the MTU of all endpoint interfaces in the host network namespace
	deviceIter := emu.deviceTable.All(rx)
	for dev := range deviceIter {
		switch dev.Type {
		case "veth", "netkit":
		default:
			continue
		}

		// Ignore virtual devices not starting with the host namespace interface prefix.
		// Assume these would be devices not under Cilium management.
		if !strings.HasPrefix(dev.Name, connector.HostInterfacePrefix) {
			continue
		}

		link, err := netlink.LinkByIndex(dev.Index)
		if err != nil {
			// Ignore any errors. It is possible that the device has been removed between the time
			// we read the device table and now.
			continue
		}

		if err := netlink.LinkSetMTU(link, defaultRouteMTU.DeviceMTU); err != nil {
			// Ignore any errors. It is possible that the device has been removed between the time
			// we got the link and now.
			continue
		}
	}

	return nil
}

// RegisterHook registers a hook to be called when updating the MTU of endpoints.
func (emu *endpointUpdater) RegisterHook(hook EndpointMTUUpdateHook) {
	emu.hooks = append(emu.hooks, hook)
}

// updateEndpoints updates all endpoints with the given route MTUs.
// It attempts to update as many endpoints as possible even if partial errors occur.
func (emu *endpointUpdater) updateEndpoints(routeMTUs []RouteMTU) error {
	files, err := os.ReadDir(defaults.NetNsPath)
	if err != nil {
		return fmt.Errorf(
			"Error opening the netns dir (%q) while updating MTU for endpoints: %w",
			defaults.NetNsPath,
			err,
		)
	}

	var errs []error

	for _, file := range files {
		ns, err := netns.OpenPinned(filepath.Join(defaults.NetNsPath, file.Name()))
		if err != nil {
			// If the netns disappeared between the time we read the directory and now, ignore it,
			// it likely means the endpoint was deleted.
			if os.IsNotExist(err) {
				continue
			}

			emu.logger.Error("Error opening netns",
				logfields.NetNSName, file.Name(),
				logfields.Error, err,
			)
			errs = append(errs, err)
			continue
		}

		err = ns.Do(func() error {
			for _, hook := range emu.hooks {
				if err := hook(routeMTUs); err != nil {
					errs = append(errs, err)
					emu.logger.Error("error while updating MTU for endpoint",
						logfields.NetNSName, file.Name(),
						logfields.Error, err,
						logfields.Hook, runtime.FuncForPC(reflect.ValueOf(hook).Pointer()).Name(),
					)
				}
			}
			return nil
		})
		ns.Close()
		// Even though we never return an error from ns.Do, it can still fail internally
		if err != nil {
			// When we open a netns, we get a file descriptor to the netns, which ns.Do uses internally
			// to do syscalls for the switching. If the netns is deleted between the time we open it and
			// the time of calling ns.Do, we get an -EINVAL error, since the file descriptor is no longer valid.
			// We ignore this error, since it means the netns and thus the endpoint was deleted.
			if errors.Is(err, unix.EINVAL) {
				continue
			}

			errs = append(errs, err)
			emu.logger.Error("error while updating MTU for endpoint",
				logfields.NetNSName, file.Name(),
				logfields.Error, err,
			)
			continue
		}
	}

	return errors.Join(errs...)
}

// This hook updates the MTU of the default route and MTU of every veth and netkit interface
func defaultRouteHook(routeMTUs []RouteMTU) error {
	defaultRouteMTU, err := defaultRoute(routeMTUs)
	if err != nil {
		return err
	}

	links, err := safenetlink.LinkList()
	if err != nil {
		return err
	}

	for _, link := range links {
		switch link.Type() {
		case "veth", "netkit":
		default:
			continue
		}

		netlink.LinkSetMTU(link, defaultRouteMTU.DeviceMTU)

		routes, err := safenetlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("netlink.RouteList failed: %w", err)
		}

		for _, rt := range routes {
			switch rt.Family {
			case netlink.FAMILY_V4, netlink.FAMILY_V6:
			default:
				continue
			}

			// Only update the MTU of the default route
			netPrefix := routeDstNetPrefix(rt)
			if !netPrefixEqual(netPrefix, DefaultPrefixV4) && !netPrefixEqual(netPrefix, DefaultPrefixV6) {
				continue
			}

			// If the next hop is dead or next hop is carrier down, skip updating the route
			// Attempting to do so would result in an error.
			if rt.Flags&unix.RTNH_F_LINKDOWN != 0 || rt.Flags&unix.RTNH_F_DEAD != 0 {
				continue
			}

			rt.MTU = defaultRouteMTU.RouteMTU
			if err := netlink.RouteChange(&rt); err != nil {
				return fmt.Errorf("netlink.RouteChange(%v) failed: %w", rt, err)
			}
		}
	}

	return nil
}

func (emu *endpointUpdater) updateHealthEndpoint(routeMTUs []RouteMTU) error {
	// The PID file is written to at a different time than the health endpoint netns file is
	// created, so we might need a few retries under certain conditions.
	// Five retries of a second each seem reasonable before reporting errors,
	// after that let the retry logic take care of it.
	const healthEPRetries = 5

	healthPIDPath := filepath.Join(option.Config.StateDir, healthDefaults.PidfilePath)

	var (
		pid int
		err error
	)

	for range healthEPRetries {
		pid, err = pidfile.Read(healthPIDPath)
		if err == nil {
			break
		}

		time.Sleep(time.Second)
	}
	if err != nil {
		return err
	}

	// If the health endpoint is not running, we don't need to update its MTU
	if pid == 0 {
		return nil
	}

	file := fmt.Sprintf("/proc/%d/ns/net", pid)
	var healthNS *netns.NetNS
	for range healthEPRetries {
		healthNS, err = netns.OpenPinned(file)
		if err == nil {
			break
		}

		time.Sleep(time.Second)
	}
	if err != nil {
		return err
	}

	var errs []error

	err = healthNS.Do(func() error {
		for _, hook := range emu.hooks {
			if err := hook(routeMTUs); err != nil {
				errs = append(errs, err)
				emu.logger.Error("error while updating MTU for health endpoint",
					logfields.NetNSName, file,
					logfields.Error, err,
					logfields.Hook, runtime.FuncForPC(reflect.ValueOf(hook).Pointer()).Name(),
				)
			}
		}
		return nil
	})
	healthNS.Close()

	// Even though we never return an error from ns.Do, it can still fail internally
	if err != nil {
		emu.logger.Error("Error updating MTU for health endpoint",
			logfields.PID, pid,
			logfields.Error, err,
		)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// convert the route destination to a netip.Prefix
func routeDstNetPrefix(rt netlink.Route) netip.Prefix {
	var toIP netip.Addr
	switch rt.Family {
	case netlink.FAMILY_V4:
		toIP, _ = netip.AddrFromSlice(rt.Dst.IP.To4())
	case netlink.FAMILY_V6:
		toIP, _ = netip.AddrFromSlice(rt.Dst.IP.To16())
	}

	ones, _ := rt.Dst.Mask.Size()
	return netip.PrefixFrom(toIP, ones)
}

func netPrefixEqual(a, b netip.Prefix) bool {
	return a.Addr() == b.Addr() && a.Bits() == b.Bits()
}

func routeMTUCmp(a, b RouteMTU) int {
	return cmp.Or(
		cmp.Compare(a.Prefix.Addr().BitLen(), b.Prefix.Addr().BitLen()),
		cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()),
		a.Prefix.Addr().Compare(b.Prefix.Addr()),
	)
}

func defaultRoute(routeMtus []RouteMTU) (RouteMTU, error) {
	for _, mtu := range routeMtus {
		if mtu.Prefix == DefaultPrefixV4 {
			return mtu, nil
		}
	}
	return RouteMTU{}, errors.New("default route MTU not found")
}
