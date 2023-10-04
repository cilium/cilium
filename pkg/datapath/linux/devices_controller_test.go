// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/testutils"
)

func withFreshNetNS(t *testing.T, test func(netns.NsHandle)) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	oldNetNS, err := netns.Get()
	assert.NoError(t, err)
	testNetNS, err := netns.New()
	assert.NoError(t, err)
	defer func() { assert.NoError(t, testNetNS.Close()) }()
	defer func() { assert.NoError(t, netns.Set(oldNetNS)) }()
	test(testNetNS)
}

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

func containsAddress(dev *tables.Device, addrStr string) bool {
	addr := netip.MustParseAddr(addrStr)
	for _, a := range dev.Addrs {
		if a.Addr == addr {
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

	routeExists := func(routes []*tables.Route, linkIndex int, dst, src string) bool {
		for _, r := range routes {
			if r.LinkIndex == linkIndex && r.Dst.String() == dst && r.Src.String() == src {
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
					routeExists(routes, devs[0].Index, "192.168.0.0/24", "192.168.0.1")
			},
		},
		{
			"add dummy1",
			func(t *testing.T) {
				// Create another dummy to check that the table updates.
				require.NoError(t, createDummy("dummy1", "192.168.1.1/24", false))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				// Since we're indexing by ifindex, we expect these to be in the order
				// they were added.
				return len(devs) == 2 &&
					"dummy0" == devs[0].Name &&
					routeExists(routes, devs[0].Index, "192.168.0.0/24", "192.168.0.1") &&
					devs[0].Selected &&
					"dummy1" == devs[1].Name &&
					devs[1].Selected &&
					routeExists(routes, devs[1].Index, "192.168.1.0/24", "192.168.1.1")
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
			"delete-dummy0",
			func(t *testing.T) {
				require.NoError(t, deleteLink("dummy0"))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 1 &&
					"dummy1" == devs[0].Name &&
					containsAddress(devs[0], "192.168.1.1")
			},
		},

		{
			"veth-with-default-gw",
			func(t *testing.T) {
				assert.NoError(t,
					addRoute(addRouteParams{iface: "veth0", gw: "192.168.4.254", table: unix.RT_TABLE_MAIN}))
			},
			func(t *testing.T, devs []*tables.Device, routes []*tables.Route) bool {
				return len(devs) == 2 &&
					devs[0].Name == "dummy1" &&
					devs[0].Selected &&
					devs[1].Name == "veth0" &&
					containsAddress(devs[1], "192.168.4.1") &&
					devs[1].Selected
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

	withFreshNetNS(t, func(ns netns.NsHandle) {

		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
			routesTable  statedb.Table[*tables.Route]
		)
		h := hive.New(
			statedb.Cell,
			tables.Cell,
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) {
				// Provide the normal netlink interface, but restrict it to the test network
				// namespace.
				return makeNetlinkFuncs(ns)
			}),

			cell.Provide(func() DevicesConfig {
				return DevicesConfig{}
			}),

			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device], routesTable_ statedb.Table[*tables.Route]) {
				db = db_
				devicesTable = devicesTable_
				routesTable = routesTable_
			}))

		// Create a dummy device before starting to exercise initialize()
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))

		err := h.Start(ctx)
		require.NoError(t, err)

		for _, step := range testSteps {
			step.prepare(t)

			// Get the new set of devices
			for {
				txn := db.ReadTxn()
				devs, devsInvalidated := tables.SelectedDevices(devicesTable, txn)

				routesIter, routesIterInvalidated := routesTable.All(txn)
				routes := statedb.Collect(routesIter)

				if step.check(t, devs, routes) {
					break
				}

				// Wait for a changes and try again.
				select {
				case <-routesIterInvalidated:
				case <-devsInvalidated:
				case <-ctx.Done():
					txn.WriteJSON(os.Stdout)
					t.Fatalf("Test case %q timed out while waiting for devices. Last devices seen: %+v", step.name, devs)
				}
			}

			if t.Failed() {
				break
			}
		}

		err = h.Stop(ctx)
		require.NoError(t, err)
	})
}

// Test that if the user specifies a device wildcard, then all devices not matching the wildcard
// will be marked as non-selected.
func TestDevicesController_Wildcards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	withFreshNetNS(t, func(ns netns.NsHandle) {

		var (
			db           *statedb.DB
			devicesTable statedb.Table[*tables.Device]
		)
		h := hive.New(
			statedb.Cell,
			tables.Cell,
			DevicesControllerCell,
			cell.Provide(func() DevicesConfig {
				return DevicesConfig{
					Devices: []string{"dummy+"},
				}
			}),
			cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs(ns) }),
			cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
				db = db_
				devicesTable = devicesTable_
			}))

		err := h.Start(ctx)
		require.NoError(t, err)
		require.NoError(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.NoError(t, createDummy("nonviable", "192.168.1.1/24", false))

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

		err = h.Stop(context.TODO())
		assert.NoError(t, err)
	})
}

func TestDevicesController_Restarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		db           *statedb.DB
		devicesTable statedb.Table[*tables.Device]
	)

	logging.SetLogLevelToDebug()

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

	h := hive.New(
		statedb.Cell,
		DevicesControllerCell,
		cell.Provide(func() DevicesConfig { return DevicesConfig{} }),
		cell.Provide(func() *netlinkFuncs { return &funcs }),
		cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
			db = db_
			devicesTable = devicesTable_
		}))

	err := h.Start(ctx)
	assert.NoError(t, err)

	for {
		rxn := db.ReadTxn()
		iter, invalidated := devicesTable.All(rxn)
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

	err = h.Stop(ctx)
	assert.NoError(t, err)

}
