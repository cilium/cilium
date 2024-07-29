// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func devicesControllerTestSetup(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(
			t,
			goleak.IgnoreCurrent(),
			// Ignore loop() and the netlink goroutines. These are left behind as netlink library has a bug
			// that causes it to be stuck in Recvfrom even after stop channel closes.
			// This is fixed by https://github.com/vishvananda/netlink/pull/793, but that has not been merged.
			// These goroutines will terminate after any route or address update.
			goleak.IgnoreTopFunction("github.com/cilium/cilium/pkg/datapath/linux.(*devicesController).loop"),
			goleak.IgnoreTopFunction("syscall.Syscall6"), // Recvfrom
		)
	})
}

const (
	secondaryAddress = true
	primaryAddress   = false
)

func containsAddress(dev *tables.Device, addrStr string, secondary bool) bool {
	addr := netip.MustParseAddr(addrStr)
	for _, a := range dev.Addrs {
		if a.Addr == addr && a.Secondary == secondary {
			return true
		}
	}
	return false
}

func TestDevicesController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	logging.SetLogLevelToDebug()

	addrToString := func(addr netip.Addr) string {
		if !addr.IsValid() {
			return ""
		}
		return addr.String()
	}

	routeExists := func(routes []*tables.Route, linkIndex int, dst, src, gw string) bool {
		for _, r := range routes {
			// undefined IP will stringify as "invalid IP", turn them into "".
			actualDst, actualSrc, actualGw := r.Dst.String(), addrToString(r.Src), addrToString(r.Gw)
			if r.LinkIndex == linkIndex && actualDst == dst && actualSrc == src &&
				actualGw == gw {
				return true
			}
		}
		return false
	}

	v4Routes := func(routes []*tables.Route) (out []*tables.Route) {
		for _, r := range routes {
			if r.Dst.Addr().Is4() {
				out = append(out, r)
			}
		}
		return
	}

	orphanRoutes := func(devs []*tables.Device, routes []*tables.Route) bool {
		indexes := map[int]bool{}
		for _, dev := range devs {
			indexes[dev.Index] = true
		}
		for _, r := range routes {
			if !indexes[r.LinkIndex] {
				// A route exists without a device.
				t.Logf("Orphan route found: %+v", r)
				return true
			}
		}
		return false
	}

	// The test steps perform an action, wait for devices table to change
	// and then validate the change. Since we may see intermediate states
	// in the devices table (as there's multiple netlink updates that may
	// be processed at different times) the check function is repeated
	// until the desired state is reached or [ctx] times out.
	testSteps := []struct {
		name    string
		prepare func(*testing.T)
		check   func(*testing.T, []*tables.Device, []*tables.Route) bool
	}{
		{
			"initial",
			func(*testing.T) {},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 1 &&
					devs[0].Name == "dummy0" &&
					devs[0].Index > 0 &&
					devs[0].Selected &&
					routeExists(routes, devs[0].Index, "192.168.0.0/24", "192.168.0.1", "")
			},
		},
		{
			"add dummy1",
			func(t *testing.T) {
				// Create another dummy to check that the table updates.
				require.NoError(t, createDummy("dummy1", "192.168.1.1/24", false))

				// Add a default route
				assert.NoError(t,
					addRoute(addRouteParams{iface: "dummy1", gw: "192.168.1.254", table: unix.RT_TABLE_MAIN}))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				// Since we're indexing by ifindex, we expect these to be in the order
				// they were added.
				return len(devs) == 2 &&
					"dummy0" == devs[0].Name &&
					routeExists(routes, devs[0].Index, "192.168.0.0/24", "192.168.0.1", "") &&
					devs[0].Selected &&
					"dummy1" == devs[1].Name &&
					devs[1].Selected &&
					routeExists(routes, devs[1].Index, "192.168.1.0/24", "192.168.1.1", "")
			},
		},

		{
			"secondary address",
			func(t *testing.T) {
				require.NoError(t, addAddrScoped("dummy1", "192.168.1.2/24", netlink.SCOPE_SITE, unix.IFA_F_SECONDARY))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				// Since we're indexing by ifindex, we expect these to be in the order
				// they were added.
				return len(devs) == 2 &&
					"dummy1" == devs[1].Name &&
					devs[1].Selected &&
					containsAddress(devs[1], "192.168.1.1", primaryAddress) &&
					containsAddress(devs[1], "192.168.1.2", secondaryAddress)
			},
		},

		{ // Only consider veth devices when they have a default route.
			"veth-without-default-gw",
			func(t *testing.T) {
				require.NoError(t, createVeth("veth0", "192.168.4.1/24", false))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				// No changes expected to previous step.
				return len(devs) == 2 &&
					"dummy0" == devs[0].Name &&
					"dummy1" == devs[1].Name
			},
		},

		{
			"veth-with-default-gw",
			func(t *testing.T) {
				// Remove default route from dummy1
				assert.NoError(t,
					delRoute(addRouteParams{iface: "dummy1", gw: "192.168.1.254", table: unix.RT_TABLE_MAIN}))

				// And add one for veth0.
				assert.NoError(t,
					addRoute(addRouteParams{iface: "veth0", gw: "192.168.4.254", table: unix.RT_TABLE_MAIN}))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 3 &&
					devs[0].Name == "dummy0" &&
					devs[1].Name == "dummy1" &&
					devs[2].Name == "veth0" &&
					containsAddress(devs[2], "192.168.4.1", primaryAddress) &&
					routeExists(routes, devs[2].Index, "0.0.0.0/0", "", "192.168.4.254")
			},
		},

		{
			"check-all-v4-routes",
			func(t *testing.T) {},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				routes = v4Routes(routes)
				json, _ := json.Marshal(routes)
				os.WriteFile("/tmp/routes.json", json, 0644)
				return routeExists(routes, devs[0].Index, "192.168.0.0/24", "192.168.0.1", "") &&
					routeExists(routes, devs[0].Index, "192.168.0.1/32", "192.168.0.1", "") &&
					routeExists(routes, devs[0].Index, "192.168.0.255/32", "192.168.0.1", "") &&

					routeExists(routes, devs[1].Index, "192.168.1.0/24", "192.168.1.1", "") &&
					routeExists(routes, devs[1].Index, "192.168.1.1/32", "192.168.1.1", "") &&
					routeExists(routes, devs[1].Index, "192.168.1.2/32", "192.168.1.1", "") &&
					routeExists(routes, devs[1].Index, "192.168.1.255/32", "192.168.1.1", "") &&

					routeExists(routes, devs[2].Index, "192.168.4.0/24", "192.168.4.1", "") &&
					routeExists(routes, devs[2].Index, "192.168.4.1/32", "192.168.4.1", "") &&
					routeExists(routes, devs[2].Index, "192.168.4.255/32", "192.168.4.1", "") &&
					routeExists(routes, devs[2].Index, "0.0.0.0/0", "", "192.168.4.254") &&
					len(routes) == 11
			},
		},

		{
			"delete-dummy0",
			func(t *testing.T) {
				require.NoError(t, deleteLink("dummy0"))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 2 &&
					"dummy1" == devs[0].Name &&
					"veth0" == devs[1].Name
			},
		},

		{
			"bond-is-selected",
			func(t *testing.T) {
				require.NoError(t, deleteLink("veth0"))
				require.NoError(t, createBond("bond0", "192.168.6.1/24", false))
				require.NoError(t, setBondMaster("dummy1", "bond0"))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				// Slaved devices are ignored, so we should only see bond0.
				return len(devs) == 1 &&
					devs[0].Name == "bond0" &&
					devs[0].Selected
			},
		},
		{
			"dummy1-restored",
			func(t *testing.T) {
				// Deleting the bond device restores dummy1 as a selected device
				// as it is no longer a slave device.
				assert.NoError(t, deleteLink("bond0"))
				assert.NoError(t, setLinkUp("dummy1"))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 1 &&
					devs[0].Name == "dummy1" &&
					devs[0].Selected
			},
		},
		{
			"skip-bridge-devices",
			func(t *testing.T) {
				require.NoError(t, createBridge("br0", "192.168.5.1/24", false))
				require.NoError(t, setMaster("dummy1", "br0"))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 0
			},
		},
	}

	tlog := hivetest.Logger(t)
	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
			routesTable  statedb.Table[*tables.Route]
		)
		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) {
				// Provide the normal netlink interface, but restrict it to the test network
				// namespace.
				return makeNetlinkFuncs()
			}),

			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device], routesTable_ statedb.Table[*tables.Route]) {
				db = db_
				devicesTable = devicesTable_
				routesTable = routesTable_
			}))

		// Create a dummy device before starting to exercise initialize()
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))

		err := h.Start(tlog, ctx)
		require.NoError(t, err)

		for _, step := range testSteps {
			step.prepare(t)

			// Get the new set of devices
			for {
				txn := db.ReadTxn()
				allDevs := statedb.Collect(devicesTable.All(txn))
				devs, devsInvalidated := tables.SelectedDevices(devicesTable, txn)

				routesIter, routesIterInvalidated := routesTable.AllWatch(txn)
				routes := statedb.Collect(routesIter)

				// Stop if the test case passes and there are no orphan routes left in the
				// route table.
				if step.check(t, devs, routes) && !orphanRoutes(allDevs, routes) {
					break
				}

				// Wait for a changes and try again.
				select {
				case <-routesIterInvalidated:
				case <-devsInvalidated:
				case <-ctx.Done():
					txn.WriteJSON(os.Stdout)
					t.Fatalf("Test case %q timed out while waiting for devices", step.name)
				}
			}

			if t.Failed() {
				break
			}
		}

		err = h.Stop(tlog, ctx)
		require.NoError(t, err)
		return nil
	})
}

// Test that if the user specifies a device wildcard, then all devices not matching the wildcard
// will be marked as non-selected.
func TestDevicesController_Wildcards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	tlog := hivetest.Logger(t)
	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
		)
		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs() }),
			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
				db = db_
				devicesTable = devicesTable_
			}))
		hive.AddConfigOverride(h, func(c *DevicesConfig) {
			c.Devices = []string{"dummy+"}
		})

		err := h.Start(tlog, ctx)
		require.NoError(t, err)
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.NoError(t, createDummy("nonviable", "192.168.1.1/24", false))

		// This device satisfies the autodetection rule, but should not be included
		// because the ForceDeviceDetection option is not enabled
		require.NoError(t, createDummy("eth0", "1.2.3.4/24", false))

		for {
			rxn := db.ReadTxn()
			devs, invalidated := tables.SelectedDevices(devicesTable, rxn)

			if len(devs) == 1 && devs[0].Name == "dummy0" {
				break
			}

			// Not yet what we expected, wait for changes and try again.
			select {
			case <-ctx.Done():
				t.Fatalf("Test timed out while waiting for devices, last seen: %v", devs)
			case <-invalidated:
			}
		}

		err = h.Stop(tlog, context.TODO())
		assert.NoError(t, err)
		return nil
	})
}

// TestDevicesController_with_ForcedDetection tests the behavior of device detection when forced detection is enabled.
// It expects all devices matching a specific pattern to be detected will append to detected devices and marked as selected.
func TestDevicesController_with_ForcedDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	tlog := hivetest.Logger(t)
	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
			h            *hive.Hive
		)

		// Function to set up the hive and run device detection
		runDeviceDetection := func(devicePattern string, forceDetection bool) error {
			h = hive.New(
				DevicesControllerCell,
				cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs() }),
				cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
					db = db_
					devicesTable = devicesTable_
				}),
			)
			hive.AddConfigOverride(h, func(c *DevicesConfig) {
				c.Devices = []string{devicePattern}
				c.ForceDeviceDetection = forceDetection
			})

			return h.Start(tlog, ctx)
		}

		// Function to check the expected number of devices
		testDevices := func(expectedCount int) bool {
			rxn := db.ReadTxn()
			devs, invalidated := tables.SelectedDevices(devicesTable, rxn)
			if len(devs) == expectedCount {
				return true
			}

			select {
			case <-ctx.Done():
				t.Fatalf("Test timed out while waiting for devices, last seen: %v", devs)
				return false
			case <-invalidated:
				return false
			}
		}

		// Create dummy interfaces as per test requirements
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.NoError(t, createDummy("dummy1", "192.168.1.1/24", false))

		// This device does not match the "dummy+" pattern, but should be included
		// because the ForceDeviceDetection option is enabled
		require.NoError(t, createDummy("eth0", "1.2.3.4/24", false))

		// Test with forced detection enabled
		require.NoError(t, runDeviceDetection("dummy+", true))
		require.True(t, testDevices(3), "Expecting all three devices to be detected")
		require.NoError(t, h.Stop(tlog, ctx))

		return nil
	})
}

func TestDevicesController_Restarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		db           *statedb.DB
		devicesTable statedb.Table[*tables.Device]
	)

	// Is this the first subscription?
	var first atomic.Bool
	first.Store(true)

	funcs := netlinkFuncs{
		AddrList: func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return nil, nil
		},

		Close: func() {},

		LinkList: func() ([]netlink.Link, error) {
			if first.Load() {
				// On first round we create a stale device that should get flushed
				// from the devices table.
				return []netlink.Link{&netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Index:        2,
						Name:         "stale",
						HardwareAddr: []byte{2, 3, 4, 5, 6, 7},
					},
				}}, nil
			}
			return nil, nil
		},

		RouteListFiltered: func(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
			return nil, nil
		},

		RouteSubscribe: func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if !first.Load() {
					_, ipn, _ := net.ParseCIDR("1.2.3.0/24")
					select {
					case <-done:
					case ch <- netlink.RouteUpdate{
						Type: unix.RTM_NEWROUTE,
						Route: netlink.Route{
							LinkIndex: 1,
							Table:     unix.RT_TABLE_DEFAULT,
							Scope:     unix.RT_SCOPE_SITE,
							Dst:       ipn,
						},
					}:
					}
				}
				<-done
			}()
			return nil
		},
		AddrSubscribe: func(ch chan<- netlink.AddrUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if !first.Load() {
					_, ipn, _ := net.ParseCIDR("1.2.3.4/24")
					select {
					case <-done:
					case ch <- netlink.AddrUpdate{
						LinkAddress: *ipn,
						LinkIndex:   1,
						NewAddr:     true,
					}:
					}
				}
				<-done
			}()
			return nil
		},
		LinkSubscribe: func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if first.Load() {
					// Simulate a netlink socket failure on the first subscription round
					errorCallback(errors.New("first"))
					first.Store(false)
				} else {
					select {
					case <-done:
					case ch <- netlink.LinkUpdate{
						IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Index: 1}},
						Header:    unix.NlMsghdr{Type: unix.RTM_NEWLINK},
						Link: &netlink.Dummy{
							LinkAttrs: netlink.LinkAttrs{
								Index:        1,
								Name:         "dummy",
								HardwareAddr: []byte{1, 2, 3, 4, 5, 6},
							},
						},
					}:
					}
				}
				<-done
			}()
			return nil
		},
	}

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	h := hive.New(
		DevicesControllerCell,
		cell.Provide(func() *netlinkFuncs { return &funcs }),
		cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
			db = db_
			devicesTable = devicesTable_
		}))

	err := h.Start(tlog, ctx)
	assert.NoError(t, err)

	for {
		rxn := db.ReadTxn()
		iter, invalidated := devicesTable.AllWatch(rxn)
		devs := statedb.Collect(iter)

		// We expect the 'stale' device to have been flushed by the restart
		// and for the 'dummy' to have appeared.
		if len(devs) == 1 && devs[0].Name == "dummy" {
			break
		}

		select {
		case <-ctx.Done():
			rxn.WriteJSON(os.Stdout)
			t.Fatalf("Test timed out while waiting for device, last seen: %v", devs)
		case <-invalidated:
		}
	}

	err = h.Stop(tlog, ctx)
	assert.NoError(t, err)

}

func createLink(linkTemplate netlink.Link, iface, ipAddr string, flagMulticast bool) error {
	var flags net.Flags
	if flagMulticast {
		flags = net.FlagMulticast
	}
	*linkTemplate.Attrs() = netlink.LinkAttrs{
		Name:  iface,
		Flags: flags,
	}

	if err := netlink.LinkAdd(linkTemplate); err != nil {
		return err
	}

	if ipAddr != "" {
		if err := addAddr(iface, ipAddr); err != nil {
			return err
		}
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	return nil
}

func deleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func createDummy(iface, ipAddr string, flagMulticast bool) error {
	return createLink(&netlink.Dummy{}, iface, ipAddr, flagMulticast)
}

func createVeth(iface, ipAddr string, flagMulticast bool) error {
	return createLink(&netlink.Veth{PeerName: iface + "_"}, iface, ipAddr, flagMulticast)
}

func createBridge(iface, ipAddr string, flagMulticast bool) error {
	return createLink(&netlink.Bridge{}, iface, ipAddr, flagMulticast)
}

func createBond(iface, ipAddr string, flagMulticast bool) error {
	bond := netlink.NewLinkBond(netlink.LinkAttrs{})
	bond.Mode = netlink.BOND_MODE_BALANCE_RR
	return createLink(bond, iface, ipAddr, flagMulticast)
}

func setLinkUp(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func setMaster(iface string, master string) error {
	masterLink, err := netlink.LinkByName(master)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetMaster(link, masterLink)
}

func setBondMaster(iface string, master string) error {
	masterLink, err := netlink.LinkByName(master)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	netlink.LinkSetDown(link)
	defer netlink.LinkSetUp(link)
	return netlink.LinkSetBondSlave(link, masterLink.(*netlink.Bond))
}
func addAddr(iface string, cidr string) error {
	return addAddrScoped(iface, cidr, netlink.SCOPE_SITE, 0)
}

func addAddrScoped(iface string, cidr string, scope netlink.Scope, flags int) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("ParseCIDR: %w", err)
	}
	ipnet.IP = ip
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("LinkByName: %w", err)
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet, Scope: int(scope), Flags: flags}); err != nil {
		return fmt.Errorf("AddrAdd: %w", err)
	}
	return nil
}

type addRouteParams struct {
	iface string
	gw    string
	src   string
	dst   string
	table int
	scope netlink.Scope
}

func addRoute(p addRouteParams) error {
	link, err := netlink.LinkByName(p.iface)
	if err != nil {
		return err
	}

	var dst *net.IPNet
	if p.dst != "" {
		_, dst, err = net.ParseCIDR(p.dst)
		if err != nil {
			return err
		}
	}

	var src net.IP
	if p.src != "" {
		src = net.ParseIP(p.src)
	}

	if p.table == 0 {
		p.table = unix.RT_TABLE_MAIN
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Src:       src,
		Gw:        net.ParseIP(p.gw),
		Table:     p.table,
		Scope:     p.scope,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}

	return nil
}

func delRoute(p addRouteParams) error {
	link, err := netlink.LinkByName(p.iface)
	if err != nil {
		return err
	}

	var dst *net.IPNet
	if p.dst != "" {
		_, dst, err = net.ParseCIDR(p.dst)
		if err != nil {
			return err
		}
	}

	var src net.IP
	if p.src != "" {
		src = net.ParseIP(p.src)
	}

	if p.table == 0 {
		p.table = unix.RT_TABLE_MAIN
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Src:       src,
		Gw:        net.ParseIP(p.gw),
		Table:     p.table,
		Scope:     p.scope,
	}
	if err := netlink.RouteDel(route); err != nil {
		return err
	}

	return nil
}
