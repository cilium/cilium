// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/statedb"
)

// DevicesControllerCell registers a controller that subscribes to network devices
// and routes via netlink and populates the devices and routes devices.
var DevicesControllerCell = cell.Module(
	"devices-controller",
	"Synchronizes the device and route tables with the kernel",

	cell.Provide(
		newDevicesController,
		newDeviceManager,
	),
	cell.Invoke(func(*devicesController) {}),
)

var (
	// batchingDuration is the amount of time to wait for more
	// addr/route/link updates before processing the batch.
	batchingDuration = 100 * time.Millisecond

	// restartWaitDuration is the amount of time to wait after
	// a netlink failure before restarting from scratch.
	restartWaitDuration = time.Second

	// Route filter to look at all routing tables.
	routeFilter = netlink.Route{
		Table: unix.RT_TABLE_UNSPEC,
	}
	routeFilterMask = netlink.RT_FILTER_TABLE
)

type DevicesConfig struct {
	// Devices is the user-specified devices to use. This can be
	// either concrete devices ("eth0,eth1"), or a wildcard "eth+".
	// If empty the devices are auto-detected according to rules defined
	// by isSelectedDevice().
	Devices []string
}

type devicesControllerParams struct {
	cell.In

	Config      DevicesConfig
	Log         logrus.FieldLogger
	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
	RouteTable  statedb.Table[*tables.Route]

	// netlinkFuncs is optional and used by tests to verify error handling behavior.
	NetlinkFuncs *netlinkFuncs `optional:"true"`
}

type devicesController struct {
	params devicesControllerParams
	log    logrus.FieldLogger

	initialized    chan struct{}
	filter         deviceFilter
	l3DevSupported bool

	cancel context.CancelFunc // controller's context is cancelled when stopped.
}

func newDevicesController(lc hive.Lifecycle, p devicesControllerParams) *devicesController {
	dc := &devicesController{
		params:      p,
		initialized: make(chan struct{}),
		filter:      deviceFilter(p.Config.Devices),
		log:         p.Log,
	}
	lc.Append(dc)
	return dc
}

func (dc *devicesController) Start(startCtx hive.HookContext) error {
	if dc.params.NetlinkFuncs == nil {
		var err error
		dc.params.NetlinkFuncs, err = makeNetlinkFuncs(netns.None())
		if err != nil {
			return err
		}

		// Only probe for L3 device support when netlink isn't mocked by tests.
		dc.l3DevSupported = probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbChangeHead) == nil
	}

	var ctx context.Context
	ctx, dc.cancel = context.WithCancel(context.Background())

	go dc.run(ctx)

	// Wait until the initial population of the tables has finished
	// successfully or the start has been aborted.
	select {
	case <-dc.initialized:
	case <-startCtx.Done():
		dc.cancel()
	}

	return nil
}

func (dc *devicesController) run(ctx context.Context) {
	defer dc.params.NetlinkFuncs.Close()

	// Run the controller in a loop and restarting on failures until stopped.
	// We're doing this as netlink is an unreliable protocol that may drop
	// messages if the socket buffer is filled (recvmsg returns ENOBUFS).
	for ctx.Err() == nil {
		dc.subscribeAndProcess(ctx)

		t, stop := inctimer.New()

		select {
		case <-ctx.Done():
			stop()
			return
		case <-t.After(restartWaitDuration):
		}
	}
}

func (dc *devicesController) subscribeAndProcess(ctx context.Context) {
	// Wrap the controller context to allow cancelling it on failures.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Callback for logging errors from the netlink subscriptions.
	// It cancels the context to unsubscribe from netlink updates
	// which stops the processing.
	errorCallback := func(err error) {
		dc.log.WithError(err).Warn("Netlink error received, restarting")

		// Cancel the context to stop the subscriptions.
		cancel()
	}

	addrUpdates := make(chan netlink.AddrUpdate)
	if err := dc.params.NetlinkFuncs.AddrSubscribe(addrUpdates, ctx.Done(), errorCallback); err != nil {
		dc.log.WithError(err).Warn("AddrSubscribe failed, restarting")
		return
	}
	routeUpdates := make(chan netlink.RouteUpdate)
	err := dc.params.NetlinkFuncs.RouteSubscribe(routeUpdates, ctx.Done(), errorCallback)
	if err != nil {
		dc.log.WithError(err).Warn("RouteSubscribe failed, restarting")
		return
	}
	linkUpdates := make(chan netlink.LinkUpdate)
	err = dc.params.NetlinkFuncs.LinkSubscribe(linkUpdates, ctx.Done(), errorCallback)
	if err != nil {
		dc.log.WithError(err).Warn("LinkSubscribe failed, restarting", err)
		return
	}

	// Initialize the tables by listing links, routes and addresses.
	// Preferably we'd just subscribe to updates with listing enabled, but
	// unfortunately netlink Go library does not mark where the initial list
	// ends and updates begin.
	err = dc.initialize()
	if err != nil {
		dc.log.WithError(err).Warn("Initialization failed, restarting")
		return
	}

	// Start processing the incremental updates until we're stopping or
	// a failure is encountered.
	dc.processUpdates(addrUpdates, routeUpdates, linkUpdates)
}

func (dc *devicesController) Stop(hive.HookContext) error {
	dc.cancel()

	// Unfortunately vishvananda/netlink is buggy and does not return from Recvfrom even
	// though the stop channel given to AddrSubscribeWithOptions or RouteSubscribeWithOptions
	// is closed. This is fixed by https://github.com/vishvananda/netlink/pull/793, which
	// isn't yet merged.
	// Due to this, we're currently not waiting here for run() to exit and thus leaving around
	// couple goroutines until some address or route change arrive.
	return nil
}

func (dc *devicesController) initialize() error {
	// Do initial listing for each address, routes and links. We cannot use
	// the 'ListExisting' option as it does not provide a mechanism to know when
	// the listing is done and the updates begin. Netlink does send a NLMSG_DONE,
	// but this is not exposed by the library.
	batch := map[int][]any{}
	links, err := dc.params.NetlinkFuncs.LinkList()
	if err != nil {
		return fmt.Errorf("LinkList failed: %w", err)
	}
	for _, link := range links {
		batch[link.Attrs().Index] = append(batch[link.Attrs().Index], netlink.LinkUpdate{
			Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link:   link,
		})
	}
	addrs, err := dc.params.NetlinkFuncs.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("AddrList failed: %w", err)
	}
	for _, addr := range addrs {
		var ipnet net.IPNet
		if addr.IPNet != nil {
			ipnet = *addr.IPNet
		}
		batch[addr.LinkIndex] = append(batch[addr.LinkIndex], netlink.AddrUpdate{
			LinkAddress: ipnet,
			LinkIndex:   addr.LinkIndex,
			Flags:       addr.Flags,
			Scope:       addr.Scope,
			PreferedLft: addr.PreferedLft,
			ValidLft:    addr.ValidLft,
			NewAddr:     true,
		})
	}
	routes, err := dc.params.NetlinkFuncs.RouteListFiltered(netlink.FAMILY_ALL, &routeFilter, routeFilterMask)
	if err != nil {
		return fmt.Errorf("RouteList failed: %w", err)
	}
	for _, route := range routes {
		batch[route.LinkIndex] = append(batch[route.LinkIndex], netlink.RouteUpdate{
			Type:  unix.RTM_NEWROUTE,
			Route: route,
		})
	}

	txn := dc.params.DB.WriteTxn(dc.params.DeviceTable, dc.params.RouteTable)

	// Flush existing data from potential prior run.
	dc.params.DeviceTable.DeleteAll(txn)
	dc.params.RouteTable.DeleteAll(txn)

	// Process the initial batch.
	dc.processBatch(txn, batch)

	devs, _ := tables.SelectedDevices(dc.params.DeviceTable, txn)
	names := tables.DeviceNames(devs)
	dc.log.WithField(logfields.Devices, names).Info("Detected initial devices")

	txn.Commit()

	select {
	case <-dc.initialized:
	default:
		close(dc.initialized)
	}

	return nil
}

func (dc *devicesController) processUpdates(
	addrUpdates chan netlink.AddrUpdate,
	routeUpdates chan netlink.RouteUpdate,
	linkUpdates chan netlink.LinkUpdate,
) {
	// Use a ticker to periodically commit the batch of updates to the device and route tables.
	// We do this to reduce the number of write transactions to the state in cases like large
	// routing tables and to reduce churn in other components that observe the devices by
	// avoiding intermediate states (e.g. devices without addresses).
	ticker := time.NewTicker(batchingDuration)
	defer ticker.Stop()

	batch := map[int][]any{}
	appendUpdate := func(index int, u any) {
		batch[index] = append(batch[index], u)
	}

	// Gather address, route and link updates into a batch and
	// periodically commit it. We loop until all channels have
	// been closed in order to release the netlink subscriptions
	// when being stopped.
	for addrUpdates != nil || routeUpdates != nil || linkUpdates != nil {
		select {
		case u, ok := <-addrUpdates:
			if !ok {
				addrUpdates = nil
			} else {
				appendUpdate(u.LinkIndex, u)
			}

		case r, ok := <-routeUpdates:
			if !ok {
				routeUpdates = nil
			} else {
				appendUpdate(r.LinkIndex, r)
			}

		case l, ok := <-linkUpdates:
			if !ok {
				linkUpdates = nil
			} else {
				appendUpdate(int(l.Index), l)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				txn := dc.params.DB.WriteTxn(dc.params.DeviceTable, dc.params.RouteTable)
				dc.processBatch(txn, batch)
				txn.Commit()
				batch = map[int][]any{}
			}
		}
	}
}

func deviceAddressFromAddrUpdate(upd netlink.AddrUpdate) tables.DeviceAddress {
	return tables.DeviceAddress{
		Addr: ip.MustAddrFromIP(upd.LinkAddress.IP),

		// ifaddrmsg.ifa_scope is uint8, vishvananda/netlink has wrong type
		Scope: uint8(upd.Scope),
	}
}

func populateFromLink(d *tables.Device, link netlink.Link) {
	a := link.Attrs()
	d.Index = a.Index
	d.MTU = a.MTU
	d.Name = a.Name
	d.HardwareAddr = a.HardwareAddr
	d.Flags = a.Flags
	d.RawFlags = a.RawFlags
	d.MasterIndex = a.MasterIndex
	d.Type = link.Type()
}

// processBatch processes a batch of address, link and route updates.
// The address and link updates are merged into a device object and upserted
// into the device table.
func (dc *devicesController) processBatch(txn statedb.WriteTxn, batch map[int][]any) {
	for index, updates := range batch {
		d, _, _ := dc.params.DeviceTable.First(txn, tables.DeviceIDIndex.Query(index))
		if d == nil {
			// Unseen device. We may receive address updates before link updates
			// and thus the only thing we know at this point is the index.
			d = &tables.Device{}
			d.Index = index
		} else {
			d = d.DeepCopy()
		}
		deviceDeleted := false

		for _, u := range updates {
			switch u := u.(type) {
			case netlink.AddrUpdate:
				addr := deviceAddressFromAddrUpdate(u)
				if u.NewAddr {
					d.Addrs = append(d.Addrs, addr)
				} else {
					i := slices.Index(d.Addrs, addr)
					if i >= 0 {
						d.Addrs = slices.Delete(d.Addrs, i, i+1)
					}
				}
			case netlink.RouteUpdate:
				r := tables.Route{
					Table:     u.Table,
					LinkIndex: index,
					Scope:     uint8(u.Scope),
					Dst:       ipnetToPrefix(u.Family, u.Dst),
				}
				r.Src, _ = netip.AddrFromSlice(u.Src)
				r.Gw, _ = netip.AddrFromSlice(u.Gw)

				if u.Type == unix.RTM_NEWROUTE {
					_, _, err := dc.params.RouteTable.Insert(txn, &r)
					if err != nil {
						dc.log.WithError(err).WithField(logfields.Route, r).Warn("Failed to insert route")
					}
				} else {
					_, _, err := dc.params.RouteTable.Delete(txn, &r)
					if err != nil {
						dc.log.WithError(err).WithField(logfields.Route, r).Warn("Failed to delete route")
					}
				}
			case netlink.LinkUpdate:
				if u.Header.Type == unix.RTM_DELLINK {
					// Mark for deletion. This may be undone if
					// the ifindex is reused.
					deviceDeleted = true
				} else {
					deviceDeleted = false
					populateFromLink(d, u.Link)
				}
			}
		}

		if deviceDeleted {
			// Remove the deleted device. The routes table will be cleaned up from the
			// route updates.
			dc.params.DeviceTable.Delete(txn, d)
		} else {
			// Recheck the viability of the device after the updates have been applied.
			d.Selected = dc.isSelectedDevice(d, txn) && len(d.Addrs) > 0

			// Create or update the device.
			_, _, err := dc.params.DeviceTable.Insert(txn, d)
			if err != nil {
				dc.log.WithError(err).WithField(logfields.Device, d).Warn("Failed to insert route")
			}
		}
	}
}

const (
	// Exclude devices that have one or more of these flags set.
	excludedIfFlagsMask uint32 = unix.IFF_SLAVE | unix.IFF_LOOPBACK

	// Require these flags to be set.
	requiredIfFlagsMask uint32 = unix.IFF_UP
)

// isSelectedDevice checks if the device is selected or not. We still maintain its state in
// case it later becomes selected.
func (dc *devicesController) isSelectedDevice(d *tables.Device, txn statedb.WriteTxn) bool {
	if d.Name == "" {
		// Looks like we have seen the addresses for this device before the initial link update,
		// hence it has no name. Definitely not selected yet!
		return false
	}

	log := dc.log.WithField(logfields.Device, d.Name)

	// Skip devices that have an excluded interface flag set.
	if d.RawFlags&excludedIfFlagsMask != 0 {
		log.Debugf("Not selecting device as it has an excluded flag set (mask=0x%x, flags=0x%x)", excludedIfFlagsMask, d.RawFlags)
		return false
	}

	// Skip devices that don't have the required flags set.
	if d.RawFlags&requiredIfFlagsMask == 0 {
		log.Debugf("Not selecting device as it is missing required flag (mask=0x%x, flags=0x%x)", requiredIfFlagsMask, d.RawFlags)
		return false
	}

	// Ignore bridge and bonding slave devices
	if d.MasterIndex != 0 {
		log.Debugf("Not selecting enslaved device (master %d)", d.MasterIndex)
		return false
	}

	// Ignore L3 devices if we cannot support them.
	hasMacAddr := len(d.HardwareAddr) != 0
	if !dc.l3DevSupported && !hasMacAddr {
		log.Info("Not selecting L3 device; >= 5.8 kernel is required.")
		return false
	}

	// If user specified devices or wildcards, then skip the device if it doesn't match.
	if !dc.filter.match(d.Name) {
		log.WithField("filter", dc.filter).Info("Not selecting non-matching device")
		return false
	}

	// Always choose a device that the user has specified, regardless of its
	// properties.
	if dc.filter.nonEmpty() {
		return true
	}

	// Never consider devices with any of the excluded devices.
	for _, p := range defaults.ExcludedDevicePrefixes {
		if strings.HasPrefix(d.Name, p) {
			log.Debugf("Not selecting device as it has excluded prefix '%s'", p)
			return false
		}
	}
	switch d.Type {
	case "veth":
		// Skip veth devices that don't have a default route (unless user has specified
		// the device manually).
		// This is a workaround for kubernetes-in-docker. We want to avoid
		// veth devices in general as they may be leftovers from another CNI.
		if !dc.filter.nonEmpty() && !tables.HasDefaultRoute(dc.params.RouteTable, txn, d.Index) {
			log.Debug("Not selecting veth device as it has no default route")
			return false
		}

	case "bridge", "openvswitch":
		// Skip bridge devices as they're very unlikely to be used for K8s
		// purposes. In the rare cases where a user wants to load datapath
		// programs onto them they can override device detection with --devices.
		log.Debug("Not selecting bridge-like device")
		return false
	}

	if !hasGlobalRoute(d.Index, dc.params.RouteTable, txn) {
		log.Debug("Not selecting device as it has no global unicast routes")
		return false
	}

	log.Debug("Selected this device")

	return true
}

func hasGlobalRoute(devIndex int, tbl statedb.Table[*tables.Route], rxn statedb.ReadTxn) bool {
	iter, _ := tbl.Get(rxn, tables.RouteLinkIndex.Query(devIndex))
	hasGlobal := false
	for r, _, ok := iter.Next(); ok; r, _, ok = iter.Next() {
		if r.Dst.Addr().IsGlobalUnicast() {
			hasGlobal = true
			break
		}
	}

	return hasGlobal
}

// deviceFilter implements filtering device names either by
// concrete name ("eth0") or by iptables-like wildcard ("eth+").
type deviceFilter []string

// nonEmpty returns true if the filter has been defined
// (i.e. user has specified --devices).
func (lst deviceFilter) nonEmpty() bool {
	return len(lst) > 0
}

// match checks whether the given device name passes the filter
func (lst deviceFilter) match(dev string) bool {
	if len(lst) == 0 {
		return true
	}
	for _, entry := range lst {
		if strings.HasSuffix(entry, "+") {
			prefix := strings.TrimRight(entry, "+")
			if strings.HasPrefix(dev, prefix) {
				return true
			}
		} else if dev == entry {
			return true
		}
	}
	return false
}

// netlinkFuncs wraps the netlink subscribe functions into a simpler interface to facilitate
// testing of the error handling paths.
type netlinkFuncs struct {
	RouteSubscribe    func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, errorCallback func(error)) error
	AddrSubscribe     func(ch chan<- netlink.AddrUpdate, done <-chan struct{}, errorCallback func(error)) error
	LinkSubscribe     func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, errorCallback func(error)) error
	Close             func()
	LinkList          func() ([]netlink.Link, error)
	AddrList          func(link netlink.Link, family int) ([]netlink.Addr, error)
	RouteListFiltered func(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
}

func makeNetlinkFuncs(netns netns.NsHandle) (*netlinkFuncs, error) {
	h, err := netlink.NewHandleAt(netns)
	if err != nil {
		return nil, fmt.Errorf("NewHandleAt failed: %w", err)
	}

	return &netlinkFuncs{
		RouteSubscribe: func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, errorCallback func(error)) error {
			return netlink.RouteSubscribeWithOptions(ch, done,
				netlink.RouteSubscribeOptions{
					ListExisting:  false,
					Namespace:     &netns,
					ErrorCallback: errorCallback,
				})
		},
		AddrSubscribe: func(ch chan<- netlink.AddrUpdate, done <-chan struct{}, errorCallback func(error)) error {
			return netlink.AddrSubscribeWithOptions(ch, done,
				netlink.AddrSubscribeOptions{
					ListExisting:  false,
					Namespace:     &netns,
					ErrorCallback: errorCallback,
				})
		},
		LinkSubscribe: func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, errorCallback func(error)) error {
			return netlink.LinkSubscribeWithOptions(ch, done,
				netlink.LinkSubscribeOptions{
					ListExisting:  false,
					Namespace:     &netns,
					ErrorCallback: errorCallback,
				})
		},
		Close:             h.Close,
		LinkList:          h.LinkList,
		AddrList:          h.AddrList,
		RouteListFiltered: h.RouteListFiltered,
	}, nil
}

func ipnetToPrefix(family int, ipn *net.IPNet) netip.Prefix {
	if ipn != nil {
		cidr, _ := ipn.Mask.Size()
		return netip.PrefixFrom(ip.MustAddrFromIP(ipn.IP), cidr)
	}
	return netip.PrefixFrom(zeroAddr(family), 0)
}

func zeroAddr(family int) netip.Addr {
	if family == nl.FAMILY_V4 {
		return netip.IPv4Unspecified()
	} else {
		return netip.IPv6Unspecified()
	}
}
