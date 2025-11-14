// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scripttest

import (
	"fmt"
	"maps"
	"net/netip"
	"os"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/scriptnet"
)

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	defer testutils.GoleakVerifyNone(t)

	// When certain kernel modules are loaded, the kernel will by default try
	// to create fallback devices in newly created network namespaces.
	// Setting net.core.fb_tunnels_only_for_init=2 will prevent the kernel from
	// creating fallback devices so we have a more predictable test environment.
	sc := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	val, _ := sc.ReadInt([]string{"net", "core", "fb_tunnels_only_for_init_net"})
	t.Log("sysctl net.core.fb_tunnels_only_for_init_net was set to ", val)
	if val != 2 {
		t.Log("Setting sysctl net.core.fb_tunnels_only_for_init_net to 2")
		sc.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, 2)

		// Lets be a good citizen and clean up after ourselves.
		t.Cleanup(func() {
			t.Log("Resetting sysctl net.core.fb_tunnels_only_for_init_net to previous value")
			sc.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, val)
		})
	}

	scripttest.Test(t,
		t.Context(),
		func(t testing.TB, args []string) *script.Engine {
			stateDir := t.TempDir()
			nsManager, err := scriptnet.NewNSManager(t)
			require.NoError(t, err, "NewNSManager")

			err = nsManager.LockThreadAndInitialize(t, true)
			require.NoError(t, err, "LockThreadAndInitialize")

			var (
				db     *statedb.DB
				drm    *reconciler.DesiredRouteManager
				devTbl statedb.Table[*tables.Device]
			)
			cells := []cell.Cell{
				reconciler.Cell,
				linux.DevicesControllerCell,
				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{
						StateDir: stateDir,
					}
				}),
				cell.Invoke(func(d *statedb.DB, m *reconciler.DesiredRouteManager, devices statedb.Table[*tables.Device]) {
					db = d
					drm = m
					devTbl = devices
				}),
			}
			h := ciliumhive.New(
				cells...,
			)

			log := hivetest.Logger(t)
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")

			maps.Copy(cmds, nsManager.Commands())
			maps.Copy(cmds, script.DefaultCmds())
			maps.Copy(cmds, testDesiredRouteCmds(db, drm, devTbl))

			e := &script.Engine{}
			cmds["hive/recreate"] = script.Command(
				script.CmdUsage{
					Summary: "Restart the hive",
				},
				func(s1 *script.State, s2 ...string) (script.WaitFunc, error) {
					newHive := ciliumhive.New(cells...)

					flags := pflag.NewFlagSet("", pflag.ContinueOnError)
					newHive.RegisterFlags(flags)

					// Set some defaults
					require.NoError(t, flags.Parse(args), "flags.Parse")

					newHiveCmds, err := newHive.ScriptCommands(log)
					if err != nil {
						return nil, err
					}

					maps.Copy(cmds, newHiveCmds)
					maps.Copy(cmds, testDesiredRouteCmds(db, drm, devTbl))

					return nil, nil
				},
			)
			e.Cmds = cmds

			return e
		}, []string{"PATH=" + os.Getenv("PATH")}, "testdata/*.txtar")
}

func testDesiredRouteCmds(db *statedb.DB, drm *reconciler.DesiredRouteManager, devTbl statedb.Table[*tables.Device]) map[string]script.Cmd {
	initializers := make(map[string]reconciler.Initializer)
	return map[string]script.Cmd{
		"add-owner": script.Command(script.CmdUsage{
			Summary: "Adds a new route owner",
			Args:    "name",
		}, func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			if _, err := drm.RegisterOwner(args[0]); err != nil {
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
				AdminDistance reconciler.AdminDistance `yaml:"adminDistance"`
				Nexthop       netip.Addr
				Src           netip.Addr
				Device        string
				DeviceIfIndex int `yaml:"deviceIfIndex"`
				MultiPath     []struct {
					Device  string
					Nexthop netip.Addr
				} `yaml:"multiPath"`
				MTU   uint32
				Scope reconciler.Scope
				Type  reconciler.Type
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

			paths := make([]*reconciler.NexthopInfo, 0, len(route.MultiPath))
			for _, p := range route.MultiPath {
				var dev *tables.Device
				if p.Device != "" {
					var found bool
					dev, _, found = devTbl.Get(db.ReadTxn(), tables.DeviceNameIndex.Query(p.Device))
					if !found {
						return nil, fmt.Errorf("device %q not found", p.Device)
					}
				}
				paths = append(paths, &reconciler.NexthopInfo{
					Device:  dev,
					Nexthop: p.Nexthop,
				})
			}

			if err := drm.UpsertRoute(reconciler.DesiredRoute{
				Owner:         owner,
				Table:         route.Table,
				Prefix:        route.Prefix,
				Priority:      route.Priority,
				AdminDistance: route.AdminDistance,
				Nexthop:       route.Nexthop,
				Device:        dev,
				MultiPath:     paths,
				Src:           route.Src,
				MTU:           route.MTU,
				Scope:         route.Scope,
				Type:          route.Type,
			}); err != nil {
				return nil, fmt.Errorf("failed to upsert routes for owner %q: %w", args[0], err)
			}

			return nil, nil
		}),
		"add-initializer": script.Command(script.CmdUsage{
			Summary: "Adds a new route initializer",
			Args:    "name",
		}, func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			initializers[args[0]] = drm.RegisterInitializer(args[0])
			return nil, nil
		}),
		"finish-initializer": script.Command(script.CmdUsage{
			Summary: "Finishes a route initializer",
			Args:    "name",
		}, func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			initializer, found := initializers[args[0]]
			if !found {
				return nil, fmt.Errorf("failed to get initializer %q", args[0])
			}

			drm.FinalizeInitializer(initializer)
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
