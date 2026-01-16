// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"log/slog"
	"maps"
	"net"
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
	"github.com/cilium/cilium/pkg/bgp"
	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/manager"
	"github.com/cilium/cilium/pkg/bgp/test/commands"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/svcrouteconfig"

	ciliumhive "github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
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
	testPeeringIPsFlag            = "test-peering-ips"
	enableNoEndpointsRoutableFlag = "enable-no-service-endpoints-routable"
	ipamFlag                      = "ipam"
	probeTCPMD5Flag               = "probe-tcp-md5"
	kubeProxyReplacementFlag      = "kube-proxy-replacement"
)

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	slog.SetLogLoggerLevel(slog.LevelDebug) // used by test GoBGP instances

	types.SetName(testNodeName)

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
		var lbWriter *writer.Writer

		// parse the shebang arguments in the script
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice(testPeeringIPsFlag, nil, "List of IPs used for peering in the test")
		ipam := flags.String(ipamFlag, ipamOption.IPAMKubernetes, "IPAM used by the test")
		probeTCPMD5 := flags.Bool(probeTCPMD5Flag, false, "Probe if TCP_MD5SIG socket option is available")
		kubeProxyReplacement := flags.Bool(kubeProxyReplacementFlag, true, "")
		noEndpointsRoutable := flags.Bool(enableNoEndpointsRoutableFlag, true, "")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		if *probeTCPMD5 {
			available, err := TCPMD5SigAvailable()
			require.NoError(t, err)
			if !available {
				t.Skip("TCP_MD5SIG socket option is not available")
			}
		}

		h := ciliumhive.New(
			metrics.Cell,

			// BGP cell
			bgp.Cell,
			svcrouteconfig.Cell,

			// Provide statedb tables
			cell.Provide(
				tables.NewRouteTable,
				tables.NewDeviceTable,
				tables.NewNodeAddressTable,
				statedb.RWTable[*tables.Route].ToTable,      // Table[*Route]
				statedb.RWTable[*tables.Device].ToTable,     // Table[*Device]
				statedb.RWTable[tables.NodeAddress].ToTable, // Table[NodeAddress]
			),

			// Dependencies
			k8sClient.FakeClientCell(),
			daemonk8s.ResourcesCell,
			daemonk8s.TablesCell,
			node.LocalNodeStoreTestCell,
			cell.Config(envoyCfg.SecretSyncConfig{}),

			// Load-balancer writer (provides Frontend table) and reflectors (populate from K8s services)
			loadbalancer.ConfigCell,
			writer.Cell,
			reflectors.Cell,
			lbipamconfig.Cell,
			nodeipamconfig.Cell,

			// Provide source.Sources for loadbalancer writer
			cell.Provide(func() source.Sources { return source.Sources{} }),

			cell.Provide(
				func() *option.DaemonConfig {
					option.Config = &option.DaemonConfig{
						EnableBGPControlPlane:     true,
						BGPSecretsNamespace:       testSecretsNamespace,
						BGPRouterIDAllocationMode: option.BGPRouterIDAllocationModeDefault,
						IPAM:                      *ipam,
						EnableIPv4:                true,
						EnableIPv6:                true,
					}
					return option.Config
				},
				func() kpr.KPRConfig {
					return kpr.KPRConfig{
						KubeProxyReplacement: *kubeProxyReplacement,
					}
				},
			),
			cell.Invoke(func(m agent.BGPRouterManager) {
				bgpMgr = m
				m.(*manager.BGPRouterManager).DestroyRouterOnStop(true) // fully destroy GoBGP server on Stop()
			}),
			cell.Invoke(func(w *writer.Writer) {
				lbWriter = w
			}),
		)

		hive.AddConfigOverride(
			h,
			func(cfg *svcrouteconfig.RoutesConfig) {
				cfg.EnableNoServiceEndpointsRoutable = *noEndpointsRoutable
			})

		hiveLog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// setup test peering IPs
		l, err := safenetlink.LinkByName(testLinkName)
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
		maps.Insert(cmds, maps.All(commands.SvcScriptCmds(lbWriter)))

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

// toNetlinkAddr converts netip.Prefix to *netlink.Addr
func toNetlinkAddr(prefix netip.Prefix) *netlink.Addr {
	pLen := 128
	if prefix.Addr().Is4() {
		pLen = 32
	}
	return &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), pLen),
		},
	}
}
