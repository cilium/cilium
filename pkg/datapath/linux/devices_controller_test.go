// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
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

func TestDevicesControllerScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	devicesControllerTestSetup(t)

	setup := func(t testing.TB, args []string) *script.Engine {
		var err error

		// Run the test in a new network namespace.
		origNS := netns.None()
		newNS := netns.None()
		runtime.LockOSThread()
		t.Cleanup(func() {
			if origNS.IsOpen() {
				netns.Set(origNS)
				origNS.Close()
			}
			if newNS.IsOpen() {
				newNS.Close()
			}
			runtime.UnlockOSThread()
		})
		origNS, err = netns.Get()
		assert.NoError(t, err)
		newNS, err = netns.New()
		assert.NoError(t, err)

		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func() (*netlinkFuncs, error) {
				// Provide the normal netlink interface, restricted to the test network namespace.
				return makeNetlinkFuncs()
			}),
		)

		log := hivetest.Logger(t)
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})

		// Parse the shebang arguments in the script.
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args), "flags.Parse")

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{"PATH=" + os.Getenv("PATH")},
		"testdata/device-*.txtar")
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

		NeighList: func(linkIndex, family int) ([]netlink.Neigh, error) { return nil, nil },

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
		NeighSubscribe: func(ch chan<- netlink.NeighUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if !first.Load() {
					select {
					case <-done:
					case ch <- netlink.NeighUpdate{
						Type: unix.RTM_NEWNEIGH,
						Neigh: netlink.Neigh{
							LinkIndex:    1,
							IP:           net.ParseIP("1.2.3.4"),
							HardwareAddr: []byte{1, 2, 3, 4, 5, 6},
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
