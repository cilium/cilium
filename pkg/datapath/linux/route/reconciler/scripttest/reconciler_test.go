// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scripttest

import (
	"fmt"
	"maps"
	"net/netip"
	"os"
	"strconv"
	"testing"

	"go.uber.org/goleak"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/scriptnet"
)

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	defer goleak.VerifyNone(t)

	scripttest.Test(t,
		t.Context(),
		func(t testing.TB, args []string) *script.Engine {
			nsManager, err := scriptnet.NewNSManager(t)
			require.NoError(t, err, "NewNSManager")

			err = nsManager.LockThreadAndInitialize(t, true)
			require.NoError(t, err, "LockThreadAndInitialize")

			var (
				db     *statedb.DB
				drm    *reconciler.DesiredRouteManager
				devTbl statedb.Table[*tables.Device]
			)
			h := ciliumhive.New(
				reconciler.Cell,
				linux.DevicesControllerCell,
				cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
				cell.Invoke(func(d *statedb.DB, m *reconciler.DesiredRouteManager, devices statedb.Table[*tables.Device]) {
					db = d
					drm = m
					devTbl = devices
				}),
			)

			log := hivetest.Logger(t)
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")

			maps.Insert(cmds, maps.All(nsManager.Commands()))
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			maps.Insert(cmds, maps.All(testDesiredRouteCmds(db, drm, devTbl)))

			e := &script.Engine{
				Cmds: cmds,
			}
			return e
		}, []string{"PATH=" + os.Getenv("PATH")}, "testdata/*.txtar")
}

func testDesiredRouteCmds(db *statedb.DB, drm *reconciler.DesiredRouteManager, devTbl statedb.Table[*tables.Device]) map[string]script.Cmd {
	return map[string]script.Cmd{
		"add-owner": script.Command(script.CmdUsage{
			Summary: "Adds a new route owner",
			Args:    "name adminDistance",
		}, func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}

			ad, err := strconv.Atoi(args[1])
			if err != nil {
				return nil, fmt.Errorf("invalid admin distance %q: %w", args[1], err)
			}

			if _, err := drm.RegisterOwner(args[0], reconciler.AdminDistance(ad)); err != nil {
				return nil, fmt.Errorf("failed to register owner %q: %w", args, err)
			}
			return nil, nil
		}),
		"add-route": script.Command(script.CmdUsage{
			Summary: "Adds a new route",
			Args:    "owner route-file",
		}, func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}

			owner, err := drm.GetOwner(args[0])
			if err != nil {
				return nil, fmt.Errorf("failed to get owner %q: %w", args[0], err)
			}

			routeFile, err := os.ReadFile(state.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("failed to read route file %q: %w", args[1], err)
			}

			type desiredRoute struct {
				Owner         *reconciler.RouteOwner
				Table         reconciler.TableID
				Prefix        netip.Prefix
				Priority      uint32
				Nexthop       netip.Addr
				Src           netip.Addr
				Device        string
				DeviceIfIndex int `yaml:"deviceIfIndex"`
				MTU           uint32
				Scope         reconciler.Scope
				Type          reconciler.Type
			}

			var route desiredRoute
			if err := yaml.Unmarshal(routeFile, &route); err != nil {
				return nil, fmt.Errorf("failed to unmarshal route file %q: %w", args[1], err)
			}

			var dev *tables.Device
			if route.Device != "" || route.DeviceIfIndex != 0 {
				var q statedb.Query[*tables.Device]
				if route.Device != "" {
					q = tables.DeviceNameIndex.Query(route.Device)
				} else if route.DeviceIfIndex != 0 {
					q = tables.DeviceIDIndex.Query(route.DeviceIfIndex)
				}

				var found bool
				dev, _, found = devTbl.Get(db.ReadTxn(), q)
				if !found {
					if route.Device != "" {
						return nil, fmt.Errorf("device %q not found", route.Device)
					} else if route.DeviceIfIndex != 0 {
						return nil, fmt.Errorf("device with index %d not found", route.DeviceIfIndex)
					}
				}
			}

			if err := drm.UpsertRoute(reconciler.DesiredRoute{
				Owner:    owner,
				Table:    route.Table,
				Prefix:   route.Prefix,
				Priority: route.Priority,
				Nexthop:  route.Nexthop,
				Device:   dev,
				Src:      route.Src,
				MTU:      route.MTU,
				Scope:    route.Scope,
				Type:     route.Type,
			}); err != nil {
				return nil, fmt.Errorf("failed to upsert routes for owner %q: %w", args[0], err)
			}

			return nil, nil
		}),
		"remove-owner": script.Command(script.CmdUsage{
			Summary: "Removes a route owner",
			Args:    "name",
		}, func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			owner, err := drm.GetOwner(args[0])
			if err != nil {
				return nil, fmt.Errorf("failed to get owner %q: %w", args[0], err)
			}

			if err := drm.RemoveOwner(owner); err != nil {
				return nil, fmt.Errorf("failed to remove owner %q: %w", args[0], err)
			}

			return nil, nil
		}),
	}
}
