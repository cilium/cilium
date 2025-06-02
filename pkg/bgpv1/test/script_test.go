// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"os"
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

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	"github.com/cilium/cilium/pkg/bgpv1/test/commands"
	"github.com/cilium/cilium/pkg/datapath/tables"

	ciliumhive "github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	testTimeout = 60 * time.Second

	// test resource names
	testNodeName         = "test-node"
	testSecretsNamespace = "kube-system"
	testLinkName         = "cilium-bgp-test"

	// test arguments
	testPeeringIPsFlag = "test-peering-ips"
	ipamFlag           = "ipam"
	probeTCPMD5Flag    = "probe-tcp-md5"
)

func TestScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	slog.SetLogLoggerLevel(slog.LevelDebug) // used by test GoBGP instances

	// setup test link
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: testLinkName},
	}
	netlink.LinkDel(dummy) // cleanup from potential previous test run
	err := netlink.LinkAdd(dummy)
	require.NoError(t, err, "error by adding test link %s", testLinkName)
	t.Cleanup(func() {
		netlink.LinkDel(dummy)
	})

	setup := func(t testing.TB, args []string) *script.Engine {
		var err error
		var bgpMgr agent.BGPRouterManager

		// parse the shebang arguments in the script
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice(testPeeringIPsFlag, nil, "List of IPs used for peering in the test")
		ipam := flags.String(ipamFlag, ipamOption.IPAMKubernetes, "IPAM used by the test")
		probeTCPMD5 := flags.Bool(probeTCPMD5Flag, false, "Probe if TCP_MD5SIG socket option is available")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		if *probeTCPMD5 {
			available, err := TCPMD5SigAvailable()
			require.NoError(t, err)
			if !available {
				t.Skip("TCP_MD5SIG socket option is not available")
			}
		}

		// Create the route and device tables
		routeTable, err := tables.NewRouteTable()
		require.NoError(t, err)

		deviceTable, err := tables.NewDeviceTable()
		require.NoError(t, err)

		// Create a cell that registers the tables with the StateDB
		registerTablesCell := cell.Module(
			"register-tables",
			"Registers the route and device tables with the StateDB",
			cell.Invoke(func(db *statedb.DB) {
				err := db.RegisterTable(routeTable)
				require.NoError(t, err)

				err = db.RegisterTable(deviceTable)
				require.NoError(t, err)
			}),
		)
		h := ciliumhive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			metrics.Cell,
			bgpv1.Cell,

			// Register the tables with the StateDB
			registerTablesCell,

			// Provide the route table
			cell.Provide(func() statedb.Table[*tables.Route] {
				return routeTable.ToTable()
			}),

			// Provide the device table
			cell.Provide(func() statedb.Table[*tables.Device] {
				return deviceTable.ToTable()
			}),

			cell.Provide(func() *option.DaemonConfig {
				// BGP Manager uses the global variable option.Config so we need to set it there as well
				option.Config = &option.DaemonConfig{
					EnableBGPControlPlane:     true,
					BGPSecretsNamespace:       testSecretsNamespace,
					BGPRouterIDAllocationMode: option.BGPRouterIDAllocationModeDefault,
					IPAM:                      *ipam,
				}
				return option.Config
			}),

			cell.Invoke(func() {
				types.SetName(testNodeName)
			}),
			cell.Invoke(func(m agent.BGPRouterManager) {
				bgpMgr = m
				m.(*manager.BGPRouterManager).DestroyRouterOnStop(true) // fully destroy GoBGP server on Stop()
			}),
		)

		hiveLog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// setup test peering IPs
		l, err := netlink.LinkByName(testLinkName)
		require.NoError(t, err)
		for _, ip := range *peeringIPs {
			ipAddr, err := netip.ParseAddr(ip)
			require.NoError(t, err)
			bits := 32
			if ipAddr.Is6() {
				bits = 128
			}
			prefix := netip.PrefixFrom(ipAddr, bits)
			err = netlink.AddrAdd(l, toNetlinkAddr(prefix))
			if err != nil && os.IsExist(err) {
				t.Fatalf("Peering address %s is probably already used by another test", ip)
			}
			require.NoError(t, err)
		}

		// set up GoBGP command
		gobgpCmdCtx := commands.NewGoBGPCmdContext()
		t.Cleanup(gobgpCmdCtx.Cleanup)

		cmds, err := h.ScriptCommands(hiveLog)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(commands.GoBGPScriptCmds(gobgpCmdCtx)))
		maps.Insert(cmds, maps.All(commands.BGPScriptCmds(bgpMgr)))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{"PATH=" + os.Getenv("PATH")},
		"testdata/*.txtar")
}
