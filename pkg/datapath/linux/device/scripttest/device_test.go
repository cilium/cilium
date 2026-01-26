// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scripttest

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"maps"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux"
	linuxdevice "github.com/cilium/cilium/pkg/datapath/linux/device"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/scriptnet"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

type desiredVlanDevice struct {
	Name         string `yaml:"name"`
	ParentDevice string `yaml:"parentDevice"`
	VlanID       int    `yaml:"vlanID"`
	MTU          int    `yaml:"mtu"`

	parentIdx int
}

func (d desiredVlanDevice) ToNetlink() (netlink.Link, error) {
	return &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        d.Name,
			MTU:         d.MTU,
			ParentIndex: d.parentIdx,
		},
		VlanId: d.VlanID,
	}, nil
}

func (d desiredVlanDevice) Properties() string {
	return fmt.Sprintf("Type=vlan, ParentDevice=%s, VlanID=%d", d.ParentDevice, d.VlanID)
}

func (d desiredVlanDevice) MarshalYAML() (any, error) {
	return map[string]any{
		"name":         d.Name,
		"parentDevice": d.ParentDevice,
		"vlanID":       d.VlanID,
		"mtu":          d.MTU,
	}, nil
}

func (d desiredVlanDevice) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":         d.Name,
		"parentDevice": d.ParentDevice,
		"vlanID":       d.VlanID,
		"mtu":          d.MTU,
	})
}

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	// When certain kernel modules are loaded, the kernel will by default try
	// to create fallback devices in newly created network namespaces.
	// For eg, in CI runs, sit0 interface gets created in all namespaces, which
	// is not in the expected devices table.
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
			t.Log("Resetting sysctl net.core.fb_tunnels_only_for_init_net to previous value", val)
			sc.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, val)
		})
	}

	scripttest.Test(
		t,
		ctx,
		scriptEngine,
		[]string{},
		"testdata/*.txtar",
	)
}

func scriptEngine(t testing.TB, args []string) *script.Engine {
	var (
		opts   []hivetest.LogOption
		db     *statedb.DB
		dm     linuxdevice.ManagerOperations
		devTbl statedb.Table[*tables.Device]
	)

	stateDir := t.TempDir()
	nsManager, err := scriptnet.NewNSManager(t)
	require.NoError(t, err, "NewNSManager")
	require.NoError(t, nsManager.LockThreadAndInitialize(t, true), "LockThreadAndInitialize")

	cells := []cell.Cell{
		linuxdevice.Cell,
		linux.DevicesControllerCell,
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				StateDir: stateDir,
			}
		}),
		cell.Invoke(func(d *statedb.DB, m linuxdevice.ManagerOperations, devices statedb.Table[*tables.Device]) {
			db = d
			dm = m
			devTbl = devices
		}),
	}
	h := ciliumhive.New(
		cells...,
	)
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}
	log := hivetest.Logger(t, opts...)
	t.Cleanup(func() {
		assert.NoError(t, h.Stop(log, context.Background()))
	})

	cmds, err := h.ScriptCommands(log)
	require.NoError(t, err, "ScriptCommands")

	maps.Insert(cmds, maps.All(script.DefaultCmds()))
	maps.Insert(cmds, maps.All(nsManager.Commands()))
	maps.Insert(cmds, maps.All(testDesiredDevicesCmds(db, dm, devTbl)))

	cmds["hive/recreate"] = script.Command(
		script.CmdUsage{
			Summary: "Restart the hive",
		},
		func(s1 *script.State, s2 ...string) (script.WaitFunc, error) {
			newHive := ciliumhive.New(cells...)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			newHive.RegisterFlags(flags)
			require.NoError(t, flags.Parse(args), "flags.Parse")

			newHiveCmds, err := newHive.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")

			maps.Insert(cmds, maps.All(newHiveCmds))
			maps.Insert(cmds, maps.All(testDesiredDevicesCmds(db, dm, devTbl)))
			return nil, nil
		},
	)
	return &script.Engine{
		Cmds:          cmds,
		RetryInterval: 10 * time.Millisecond,
	}
}

func testDesiredDevicesCmds(db *statedb.DB, dm linuxdevice.ManagerOperations, devTbl statedb.Table[*tables.Device]) map[string]script.Cmd {
	initializers := make(map[string]linuxdevice.Initializer)
	addDeviceCmd := script.Command(
		script.CmdUsage{
			Summary: "Add a device",
			Args:    "owner device-file",
		},
		func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}

			owner := dm.GetOrRegisterOwner(args[0])

			deviceFile, err := os.ReadFile(state.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("failed to read device file %q: %w", args[1], err)
			}

			var device desiredVlanDevice
			if err := yaml.Unmarshal(deviceFile, &device); err != nil {
				return nil, fmt.Errorf("failed to unmarshal device file %q: %w", args[1], err)
			}

			dev, _, found := devTbl.Get(db.ReadTxn(), tables.DeviceNameIndex.Query(device.ParentDevice))
			if !found {
				return nil, fmt.Errorf("parent device %q not found for VLAN device %q", device.ParentDevice, device.Name)
			}
			device.parentIdx = dev.Index

			if err := dm.UpsertDevice(linuxdevice.DesiredDevice{
				Owner:      owner,
				Name:       device.Name,
				DeviceSpec: device,
			}); err != nil {
				return nil, fmt.Errorf("failed to upsert device %q: %w", device.Name, err)
			}

			return nil, nil
		},
	)

	removeOwnerCmd := script.Command(
		script.CmdUsage{
			Summary: "Remove an owner",
			Args:    "owner",
		},
		func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			owner := dm.GetOrRegisterOwner(args[0])

			if err := dm.RemoveOwner(owner); err != nil {
				return nil, fmt.Errorf("failed to remove owner %q: %w", args[0], err)
			}

			return nil, nil
		},
	)
	addInitializer := script.Command(
		script.CmdUsage{
			Summary: "Add device initializer",
			Args:    "name",
		},
		func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			initializers[args[0]] = dm.RegisterInitializer(args[0])
			return nil, nil
		},
	)
	finishInitializer := script.Command(
		script.CmdUsage{
			Summary: "Finish device initializer",
			Args:    "name",
		},
		func(state *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			initializer, ok := initializers[args[0]]
			if !ok {
				return nil, fmt.Errorf("initializer %q not found", args[0])
			}
			dm.FinalizeInitializer(initializer)
			return nil, nil
		},
	)

	return map[string]script.Cmd{
		"add-device":         addDeviceCmd,
		"remove-owner":       removeOwnerCmd,
		"add-initializer":    addInitializer,
		"finish-initializer": finishInitializer,
	}
}
