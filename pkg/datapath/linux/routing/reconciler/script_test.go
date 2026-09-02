// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	awsAgent "github.com/cilium/cilium/pkg/aws/agent"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	routingReconciler "github.com/cilium/cilium/pkg/datapath/linux/routing/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	sysctlFake "github.com/cilium/cilium/pkg/datapath/linux/sysctl/fake"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	fqdnRules "github.com/cilium/cilium/pkg/fqdn/rules"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamcell "github.com/cilium/cilium/pkg/ipam/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipmasq"
	k8sClientTest "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
	mtuFake "github.com/cilium/cilium/pkg/mtu/fake"
	"github.com/cilium/cilium/pkg/node"
	nodeFake "github.com/cilium/cilium/pkg/node/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testmonitor "github.com/cilium/cilium/pkg/testutils/monitor"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/testutils/scriptnet"
	"github.com/cilium/cilium/pkg/time"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

const (
	testENILinkName = "cilium-rr-test"
	testENILinkMAC  = "02:ca:fe:00:00:01"
)

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	defer testutils.GoleakVerifyNone(t,
		// Endpoint-manager policy-map pressure triggers live for the process lifetime.
		// Disable them to avoid a false negative from Goleak.
		testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	nodeTypes.SetName("test-node")

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			daemonCfg := daemonConfig(t, args)
			daemonCfg.StateDir = t.TempDir()

			nsManager, err := scriptnet.NewNSManager(t)
			require.NoError(t, err, "NewNSManager")

			// Keep the test in the process network namespace so asynchronous ENI
			// provider jobs operate on the links created by the script.
			require.NoError(t, nsManager.LockThreadAndInitialize(t, false), "LockThreadAndInitialize")

			// Remove state left by an interrupted prior run, and register the same
			// cleanup in case this scenario fails before removing its state.
			registerTestCleanup(t)

			restorerResolver, restorerPromise := promise.New[endpointstate.Restorer]()
			restorerResolver.Resolve(fakeRestorer{})

			var (
				initializer   *ipamcell.IPAMInitializer
				ipamManager   *ipam.IPAM
				epManager     endpointmanager.EndpointManager
				routingWaiter endpointmanager.EndpointRoutingWaiter
			)

			h := hive.New(
				k8sClientTest.FakeClientCell(),
				agentK8s.ResourcesCell,
				k8sTables.TablesCell,
				datapathTables.DirectRoutingDeviceCell,
				endpointmanager.TestCell,

				// Exercise the production ENI pool accessor, device configurator,
				// native-routing-CIDR observer, and routing metadata resolver.
				awsAgent.Cell,
				ipamcell.Cell,
				routingReconciler.Cell,

				cell.Config(metrics.RegistryConfig{}),
				cell.Provide(
					metrics.NewRegistry,
					func() *option.DaemonConfig { return daemonCfg },
					func() *node.LocalNodeStore {
						localNode := node.LocalNode{
							Node: nodeTypes.Node{
								Name: nodeTypes.GetName(),
							},
							Local: &node.LocalNodeInfo{},
						}
						if daemonCfg.EnableIPv4 {
							localNode.IPv4AllocCIDR = nodeTypes.PrefixFrom(netip.MustParsePrefix("192.0.2.0/24"))
						}
						if daemonCfg.EnableIPv6 {
							localNode.IPv6AllocCIDR = nodeTypes.PrefixFrom(netip.MustParsePrefix("2001:db8:1::/80"))
						}
						return node.NewTestLocalNodeStore(localNode)
					},
					func() node.Addressing { return nodeFake.NewAddressing() },
					func() *watchers.K8sEventReporter { return &watchers.K8sEventReporter{} },
					func() *nodediscovery.NodeDiscovery { return &nodediscovery.NodeDiscovery{} },
					func() *ipmasq.IPMasqAgent { return nil },
					func() mtu.MTU { return &mtuFake.MTU{} },
					func() sysctl.Sysctl { return &sysctlFake.Sysctl{} },
					func() monitorAgent.Agent { return &testmonitor.TestMonitorAgent{} },
					func() promise.Promise[endpointstate.Restorer] { return restorerPromise },
					datapathTables.NewDeviceTable,
					statedb.RWTable[*datapathTables.Device].ToTable,
				),
				cell.Invoke(func(
					initializer_ *ipamcell.IPAMInitializer,
					ipamManager_ *ipam.IPAM,
					epManager_ endpointmanager.EndpointManager,
					routingWaiter_ endpointmanager.EndpointRoutingWaiter,
				) {
					initializer = initializer_
					ipamManager = ipamManager_
					epManager = epManager_
					routingWaiter = routingWaiter_
				}),
			)

			log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.Background()))
			})

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Copy(cmds, script.DefaultCmds())
			maps.Copy(cmds, nsManager.Commands())
			maps.Copy(cmds, cloudEndpointCommands(
				log, daemonCfg, initializer, ipamManager, epManager, routingWaiter,
			))

			return &script.Engine{Cmds: cmds}
		},
		[]string{"PATH=" + os.Getenv("PATH")},
		"testdata/*.txtar",
		scripttest.NoParallel,
	)
}

func daemonConfig(t testing.TB, args []string) *option.DaemonConfig {
	t.Helper()

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	families := flags.StringArray("family", nil, "address family to enable")
	require.NoError(t, flags.Parse(args))

	daemonCfg := *option.Config
	daemonCfg.EnableIPv4 = false
	daemonCfg.EnableIPv6 = false
	for _, family := range *families {
		switch family {
		case "ipv4":
			daemonCfg.EnableIPv4 = true
		case "ipv6":
			daemonCfg.EnableIPv6 = true
		default:
			t.Fatalf("unsupported address family %q", family)
		}
	}
	if !daemonCfg.EnableIPv4 && !daemonCfg.EnableIPv6 {
		t.Fatal("at least one address family must be enabled")
	}
	daemonCfg.EnableCiliumNodeCRD = true
	daemonCfg.EnableUnreachableRoutes = false
	daemonCfg.IPAM = ipamOption.IPAMENI
	daemonCfg.IPAMCiliumNodeUpdateRate = time.Nanosecond
	daemonCfg.IPv4Range = "auto"
	daemonCfg.IPv6Range = "auto"

	// Some endpoint and IPAM lifecycle paths still read the global config,
	// so keep it aligned with the config provided through Hive.
	oldDaemonConfig := option.Config
	option.Config = &daemonCfg
	t.Cleanup(func() { option.Config = oldDaemonConfig })

	return &daemonCfg
}

func registerTestCleanup(t testing.TB) {
	t.Helper()

	require.NoError(t, cleanupTestState())

	t.Cleanup(func() {
		assert.NoError(t, cleanupTestState())
	})
}

func cleanupTestState() error {
	var cleanupErrors []error

	// The privileged test environment assumes that any Cilium-shaped endpoint
	// rules were left by a previous run of this test.
	if err := linuxrouting.GCOrphanRules(slog.Default(), func(netip.Addr) bool { return true }); err != nil {
		cleanupErrors = append(cleanupErrors,
			fmt.Errorf("delete Cilium endpoint routing rules: %w", err))
	}

	link, err := safenetlink.LinkByName(testENILinkName)
	switch {
	case errors.As(err, new(netlink.LinkNotFoundError)):
		// The link is absent before the first run or was already removed.
	case err != nil:
		cleanupErrors = append(cleanupErrors,
			fmt.Errorf("look up test ENI link: %w", err))
	case link.Attrs().HardwareAddr.String() != testENILinkMAC:
		cleanupErrors = append(cleanupErrors, fmt.Errorf(
			"refusing to delete link %q with unexpected MAC %s",
			testENILinkName,
			link.Attrs().HardwareAddr,
		))
	default:
		if err := netlink.LinkDel(link); err != nil && !errors.Is(err, unix.ENODEV) {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("delete test ENI link: %w", err))
		}
	}

	return errors.Join(cleanupErrors...)
}

func cloudEndpointCommands(
	logger *slog.Logger,
	daemonCfg *option.DaemonConfig,
	initializer *ipamcell.IPAMInitializer,
	ipamManager *ipam.IPAM,
	epManager endpointmanager.EndpointManager,
	routingWaiter endpointmanager.EndpointRoutingWaiter,
) map[string]script.Cmd {
	endpoints := map[string]*endpoint.Endpoint{}
	policyRepo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo.ID, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())

	return map[string]script.Cmd{
		"ipam/start": script.Command(
			script.CmdUsage{Summary: "Start agent IPAM"},
			func(state *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 0 {
					return nil, script.ErrUsage
				}
				return nil, initializer.ConfigureAndStartIPAM(state.Context())
			},
		),
		"ipam/restore-finished": script.Command(
			script.CmdUsage{Summary: "Finish IPAM restoration"},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 0 {
					return nil, script.ErrUsage
				}
				initializer.RestoreFinished()
				return nil, nil
			},
		),
		"endpoint/add": script.Command(
			script.CmdUsage{
				Summary: "Allocate an ENI address, publish an endpoint, and wait for its routing state",
				Args:    "container-id expected-address...",
			},
			func(state *script.State, args ...string) (script.WaitFunc, error) {
				expectedAddressCount := 0
				if daemonCfg.EnableIPv4 {
					expectedAddressCount++
				}
				if daemonCfg.EnableIPv6 {
					expectedAddressCount++
				}
				if len(args) != 1+expectedAddressCount {
					return nil, script.ErrUsage
				}

				containerID := args[0]
				if _, found := endpoints[containerID]; found {
					return nil, fmt.Errorf("endpoint %q already exists", containerID)
				}

				expectedIPv4, expectedIPv6, err := expectedEndpointPrefixes(
					daemonCfg.EnableIPv4, daemonCfg.EnableIPv6, args[1:]...,
				)
				if err != nil {
					return nil, err
				}

				family := ""
				switch {
				case daemonCfg.EnableIPv4 && !daemonCfg.EnableIPv6:
					family = "ipv4"
				case daemonCfg.EnableIPv6 && !daemonCfg.EnableIPv4:
					family = "ipv6"
				}

				ipv4Result, ipv6Result, err := ipamManager.AllocateNext(family, "default/"+containerID, ipam.PoolDefault())
				if err != nil {
					return nil, fmt.Errorf("allocate endpoint address: %w", err)
				}
				releaseResults := func() error {
					return releaseAllocationResults(ipamManager, ipv4Result, ipv6Result)
				}
				if daemonCfg.EnableIPv4 && ipv4Result == nil {
					return nil, errors.Join(errors.New("IPAM returned no IPv4 allocation result"), releaseResults())
				}
				if daemonCfg.EnableIPv6 && ipv6Result == nil {
					return nil, errors.Join(errors.New("IPAM returned no IPv6 allocation result"), releaseResults())
				}

				if ipv4Result != nil && !expectedIPv4.Contains(ipv4Result.IP) {
					return nil, errors.Join(
						fmt.Errorf("allocated IPv4 address %s outside expected prefix %s", ipv4Result.IP, expectedIPv4),
						releaseResults(),
					)
				}
				if ipv6Result != nil && !expectedIPv6.Contains(ipv6Result.IP) {
					return nil, errors.Join(
						fmt.Errorf("allocated IPv6 address %s outside expected prefix %s", ipv6Result.IP, expectedIPv6),
						releaseResults(),
					)
				}

				addressing := &models.AddressPair{}
				if ipv4Result != nil {
					addressing.IPv4 = ipv4Result.IP.String()
					addressing.IPv4PoolName = string(ipv4Result.IPPoolName)
				}
				if ipv6Result != nil {
					addressing.IPv6 = ipv6Result.IP.String()
					addressing.IPv6PoolName = string(ipv6Result.IPPoolName)
				}
				endpointState := models.EndpointStateReady
				ep, err := endpoint.NewEndpointFromChangeModel(
					endpoint.EndpointParams{
						Logger:          logger,
						EPBuildQueue:    &endpoint.MockEndpointBuildQueue{},
						PolicyRepo:      policyRepo,
						IdentityManager: identitymanager.NewIDManager(logger),
						IPSecConfig:     fakeipsec.Config{},
						WgConfig:        fakewireguard.Config{},
						CTMapGC:         ctmap.NewFakeGCRunner(),
						Allocator:       testidentity.NewMockIdentityAllocator(nil),
					},
					fqdnRules.NewDNSRulesService(logger, nil, policyRepo),
					&endpoint.FakeEndpointProxy{},
					&models.EndpointChangeRequest{
						ContainerID:            containerID,
						ContainerInterfaceName: "eth0",
						State:                  &endpointState,
						Addressing:             addressing,
					},
					nil,
				)
				if err != nil {
					return nil, errors.Join(fmt.Errorf("build endpoint: %w", err), releaseResults())
				}

				if err := epManager.AddEndpoint(ep); err != nil {
					ep.Stop()
					return nil, errors.Join(fmt.Errorf("add endpoint: %w", err), releaseResults())
				}
				endpoints[containerID] = ep

				if err := routingWaiter.WaitForEndpointRouting(state.Context(), ep); err != nil {
					delete(endpoints, containerID)

					// Avoid unrelated endpoint datapath cleanup while still exercising the
					// real endpoint-manager deletion notification and IPAM release paths.
					ep.SetPropertyValue(endpointTypes.PropertyFakeEndpoint, true)
					cleanupErr := errors.Join(epManager.RemoveEndpoint(ep, endpoint.DeleteConfig{NoIdentityRelease: true})...)
					return nil, errors.Join(fmt.Errorf("wait for endpoint routing: %w", err), cleanupErr)
				}

				return func(*script.State) (stdout, stderr string, err error) {
					addresses := make([]string, 0, 2)
					if ipv4Result != nil {
						addresses = append(addresses, ipv4Result.IP.String())
					}
					if ipv6Result != nil {
						addresses = append(addresses, ipv6Result.IP.String())
					}
					return strings.Join(addresses, "\n") + "\n", "", nil
				}, nil
			},
		),
		"endpoint/del": script.Command(
			script.CmdUsage{
				Summary: "Remove an endpoint and release its ENI address",
				Args:    "container-id",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, script.ErrUsage
				}
				ep, found := endpoints[args[0]]
				if !found {
					return nil, fmt.Errorf("endpoint %q not found", args[0])
				}

				delete(endpoints, args[0])

				// Avoid unrelated endpoint datapath cleanup while still exercising the
				// real endpoint-manager deletion notification and IPAM release paths.
				ep.SetPropertyValue(endpointTypes.PropertyFakeEndpoint, true)
				return nil, errors.Join(epManager.RemoveEndpoint(ep, endpoint.DeleteConfig{NoIdentityRelease: true})...)
			},
		),
	}
}

func expectedEndpointPrefixes(enableIPv4, enableIPv6 bool, args ...string) (ipv4, ipv6 netip.Prefix, err error) {
	for _, arg := range args {
		prefix, parseErr := netip.ParsePrefix(arg)
		if parseErr != nil {
			addr, addrErr := netip.ParseAddr(arg)
			if addrErr != nil {
				return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("parse expected endpoint address or prefix %q: %w", arg, parseErr)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}

		switch {
		case prefix.Addr().Is4() && !enableIPv4:
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("IPv4 prefix %s provided while IPv4 is disabled", prefix)
		case prefix.Addr().Is4():
			ipv4 = prefix
		case !enableIPv6:
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("IPv6 prefix %s provided while IPv6 is disabled", prefix)
		default:
			ipv6 = prefix
		}
	}

	if enableIPv4 && !ipv4.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, errors.New("no expected IPv4 address or prefix provided")
	}
	if enableIPv6 && !ipv6.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, errors.New("no expected IPv6 address or prefix provided")
	}
	return ipv4, ipv6, nil
}

func releaseAllocationResults(ipamManager *ipam.IPAM, results ...*ipam.AllocationResult) error {
	var errs []error
	for _, result := range results {
		if result != nil {
			errs = append(errs, ipamManager.ReleaseIP(result.IP, result.IPPoolName))
		}
	}
	return errors.Join(errs...)
}

type fakeRestorer struct{}

func (fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error { return nil }
func (fakeRestorer) WaitForEndpointRestore(context.Context) error                    { return nil }
func (fakeRestorer) WaitForInitialPolicy(context.Context) error                      { return nil }
