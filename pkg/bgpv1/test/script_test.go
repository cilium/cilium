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
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/test/commands"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	testTimeout  = 60 * time.Second
	testLinkName = "cilium-bgp-test"
)

func TestScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	slog.SetLogLoggerLevel(slog.LevelInfo)

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

		h := ciliumhive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			metrics.Cell,
			bgpv1.Cell,

			cell.Provide(func() *option.DaemonConfig {
				// BGP Manager uses the global variable option.Config so we need to set it there as well
				option.Config = &option.DaemonConfig{
					EnableBGPControlPlane:     true,
					BGPSecretsNamespace:       "bgp-secrets",
					BGPRouterIDAllocationMode: defaults.BGPRouterIDAllocationMode,
					IPAM:                      ipamOption.IPAMKubernetes,
				}
				return option.Config
			}),

			cell.Invoke(func() {
				types.SetName("test-node")
			}),
			cell.Invoke(func(m agent.BGPRouterManager) {
				bgpMgr = m
			}),
		)

		hiveLog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// parse the shebang arguments in the script.
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice("test-peering-ips", nil, "List of IPs used for peering in the test")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

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
