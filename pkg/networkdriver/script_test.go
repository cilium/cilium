// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
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
	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/daemon/k8s"
	operatoripam "github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

const testLocalNodeName = "test-local-node"

func TestScript(t *testing.T) {
	testCases := []struct {
		name    string
		pattern string
		ipv4    bool
		ipv6    bool
	}{
		{
			name:    "dualstack",
			pattern: "testdata/dualstack/*.txtar",
			ipv4:    true,
			ipv6:    true,
		},
		{
			name:    "v4-singlestack",
			pattern: "testdata/v4-singlestack/*.txtar",
			ipv4:    true,
			ipv6:    false,
		},
		{
			name:    "v6-singlestack",
			pattern: "testdata/v6-singlestack/*.txtar",
			ipv4:    false,
			ipv6:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer testutils.GoleakVerifyNone(t)

			const (
				testDevice = "test-device"
				testDriver = "test.cilium.k8s.io"
			)

			var (
				daemonCfg = &option.DaemonConfig{
					EnableCiliumNetworkDriver: true,
					EnableIPv4:                tc.ipv4,
					EnableIPv6:                tc.ipv6,
					IPAMCiliumNodeUpdateRate:  time.Nanosecond,
				}

				mgr            *ipam.MultiPoolManager
				cs             *k8sClient.FakeClientset
				pods           resource.Resource[*corev1.Pod]
				db             *statedb.DB
				netCfgs        statedb.Table[resourceNetworkConfig]
				localNodeStore *node.LocalNodeStore
			)

			// The Kubernetes resources below capture nodeTypes.GetName while the
			// hive is built, so seed the test node before constructing them.
			origNodeName := nodetypes.GetName()
			nodetypes.SetName(testLocalNodeName)
			t.Cleanup(func() { nodetypes.SetName(origNodeName) })

			scripttest.Test(t,
				t.Context(),
				func(t testing.TB, args []string) *script.Engine {
					h := hive.New(
						k8sClient.FakeClientCell(),
						k8s.ResourcesCell,
						cell.Config(cmtypes.DefaultClusterInfo),
						node.LocalNodeStoreCell,
						cell.Provide(
							podResource,
							func() node.LocalNodeSynchronizer {
								return testLocalNodeSynchronizer{}
							},
							func() *option.DaemonConfig {
								return daemonCfg
							},
							func() promise.Promise[synced.CRDSync] {
								r, p := promise.New[synced.CRDSync]()
								r.Resolve(synced.CRDSync{})
								return p
							},
							newResourceNetworkConfigTableAndReflector,
						),
						operatoripam.Cell,
						resourceIPAM,

						cell.Invoke(func(
							mgr_ *ipam.MultiPoolManager,
							cs_ *k8sClient.FakeClientset,
							pods_ resource.Resource[*corev1.Pod],
							db_ *statedb.DB,
							netCfgs_ statedb.Table[resourceNetworkConfig],
							localNodeStore_ *node.LocalNodeStore,
						) {
							mgr = mgr_
							cs = cs_
							pods = pods_
							db = db_
							netCfgs = netCfgs_
							localNodeStore = localNodeStore_
						}),
					)

					flags := pflag.NewFlagSet("", pflag.ContinueOnError)
					h.RegisterFlags(flags)

					log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
					t.Cleanup(func() {
						assert.NoError(t, h.Stop(log, context.Background()))
					})

					// Must be executed before creating the driver, so that
					// the Invoke above is run and mgr, cs and pods are not nil.
					cmds, err := h.ScriptCommands(log)
					require.NoError(t, err, "ScriptCommands")

					driver := &Driver{
						logger:     log,
						kubeClient: cs,
						pods:       pods,
						config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
							DriverName: testDriver,
						},
						devices: map[types.DeviceManagerType][]types.Device{
							types.DeviceManagerTypeDummy: {
								&dummy.DummyDevice{
									Name: testDevice,
								},
							},
						},
						allocations:            make(map[kubetypes.UID]map[kubetypes.UID][]allocation),
						multiPoolMgr:           mgr,
						ipv4Enabled:            daemonCfg.IPv4Enabled(),
						ipv6Enabled:            daemonCfg.IPv6Enabled(),
						db:                     db,
						resourceNetworkConfigs: netCfgs,
						localNodeStore:         localNodeStore,
					}

					maps.Insert(cmds, maps.All(script.DefaultCmds()))
					maps.Insert(cmds, maps.All(commands(t.Context(), driver, cs, mgr, daemonCfg.IPv4Enabled(), daemonCfg.IPv6Enabled())))

					return &script.Engine{Cmds: cmds}
				}, []string{}, tc.pattern)
		})
	}
}

func commands(
	ctx context.Context,
	driver *Driver,
	cs *k8sClient.FakeClientset,
	mgr *ipam.MultiPoolManager,
	enableIPv4 bool,
	enableIPv6 bool,
) map[string]script.Cmd {
	return map[string]script.Cmd{
		"driver/ipam/restore-finished": script.Command(
			script.CmdUsage{
				Summary: "Mark IPAM restore as finished for enabled IP families",
				Args:    "",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 0 {
					return nil, script.ErrUsage
				}

				if enableIPv4 {
					mgr.RestoreFinished(ipam.IPv4)
				}
				if enableIPv6 {
					mgr.RestoreFinished(ipam.IPv6)
				}

				return nil, nil
			},
		),
		"driver/check-claim-addresses": script.Command(
			script.CmdUsage{
				Summary: "Check claim device addresses against local CiliumNode allocated resource pool CIDRs",
				Args:    "claim device pool",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 3 {
					return nil, script.ErrUsage
				}

				obj, err := toNamespacedName(args[0])
				if err != nil {
					return nil, err
				}

				claim, err := cs.ResourceV1().ResourceClaims(obj.Namespace).Get(ctx, obj.Name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}

				localNode, err := driver.localNodeStore.Get(ctx)
				if err != nil {
					return nil, fmt.Errorf("failed to get local node: %w", err)
				}

				return nil, checkClaimAddresses(ctx, cs, claim, driver.config.DriverName, args[1], args[2], localNode.Name)
			},
		),
		"driver/prepare-resource-claims": script.Command(
			script.CmdUsage{
				Summary: "Call PrepareResourceClaims to prepare resources",
				Args:    "claims",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) == 0 {
					return nil, script.ErrUsage
				}

				var claims []*resourcev1.ResourceClaim
				for _, arg := range args {
					obj, err := toNamespacedName(arg)
					if err != nil {
						return nil, err
					}

					claim, err := cs.ResourceV1().ResourceClaims(obj.Namespace).Get(ctx, obj.Name, metav1.GetOptions{})
					if err != nil {
						return nil, err
					}
					claims = append(claims, claim)
				}

				results, err := driver.PrepareResourceClaims(ctx, claims)
				if err != nil {
					return nil, err
				}
				for _, claim := range claims {
					result := results[claim.UID]
					if result.Err != nil {
						return nil, fmt.Errorf("failed to prepare resource claim %s/%s: %w", claim.Namespace, claim.Name, result.Err)
					}
				}

				return nil, nil
			},
		),
		"driver/unprepare-resource-claims": script.Command(
			script.CmdUsage{
				Summary: "Call UprepareResourceClaims to release resources",
				Args:    "claims",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) == 0 {
					return nil, script.ErrUsage
				}

				var claims []kubeletplugin.NamespacedObject

				for _, arg := range args {
					obj, err := toNamespacedName(arg)
					if err != nil {
						return nil, err
					}

					claim, err := cs.ResourceV1().ResourceClaims(obj.Namespace).Get(ctx, obj.Name, metav1.GetOptions{})
					if err != nil {
						return nil, err
					}

					claims = append(claims, kubeletplugin.NamespacedObject{
						NamespacedName: kubetypes.NamespacedName{
							Namespace: claim.Namespace,
							Name:      claim.Name,
						},
						UID: claim.UID,
					})
				}

				_, err := driver.UnprepareResourceClaims(ctx, claims)

				return nil, err
			},
		),
	}
}

func checkClaimAddresses(
	ctx context.Context,
	cs *k8sClient.FakeClientset,
	claim *resourcev1.ResourceClaim,
	driverName string,
	deviceName string,
	poolName string,
	nodeName string,
) error {
	addresses, err := claimDeviceAddresses(claim, driverName, deviceName)
	if err != nil {
		return err
	}

	node, err := cs.CiliumV2().CiliumNodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	allocatedCIDRs, found := nodeResourcePoolCIDRs(node.Spec.IPAM.ResourcePools.Allocated, poolName)
	if !found {
		return fmt.Errorf("CiliumNode %s has no allocated CIDRs for pool %s", nodeName, poolName)
	}

	for _, prefix := range addresses {
		addr := prefix.Addr()
		if !cidrsContainAddress(allocatedCIDRs, addr) {
			return fmt.Errorf("address %s for device %s is not part of CiliumNode %s allocated CIDRs for pool %s", prefix, deviceName, nodeName, poolName)
		}
	}
	return nil
}

func claimDeviceAddresses(claim *resourcev1.ResourceClaim, driverName, deviceName string) ([]netip.Prefix, error) {
	for _, status := range claim.Status.Devices {
		if status.Driver != driverName || status.Device != deviceName {
			continue
		}
		if status.NetworkData == nil || len(status.NetworkData.IPs) == 0 {
			return nil, fmt.Errorf("device %s has no network data IPs", deviceName)
		}

		addresses := make([]netip.Prefix, 0, len(status.NetworkData.IPs))
		for _, ip := range status.NetworkData.IPs {
			prefix, err := netip.ParsePrefix(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid address %s for device %s: %w", ip, deviceName, err)
			}
			addresses = append(addresses, prefix)
		}
		return addresses, nil
	}
	return nil, fmt.Errorf("device %s not found in claim %s/%s", deviceName, claim.Namespace, claim.Name)
}

func cidrsContainAddress(cidrs []netip.Prefix, addr netip.Addr) bool {
	for _, cidr := range cidrs {
		if cidr.Contains(addr) {
			return true
		}
	}
	return false
}

func nodeResourcePoolCIDRs(allocations []ipamTypes.IPAMPoolAllocation, poolName string) ([]netip.Prefix, bool) {
	for _, allocation := range allocations {
		if allocation.Pool != poolName {
			continue
		}
		if len(allocation.CIDRs) == 0 {
			return nil, false
		}
		cidrs := make([]netip.Prefix, 0, len(allocation.CIDRs))
		for _, cidr := range allocation.CIDRs {
			cidrs = append(cidrs, cidr.Prefix)
		}
		return cidrs, true
	}
	return nil, false
}

func toNamespacedName(s string) (kubetypes.NamespacedName, error) {
	tokens := strings.Split(s, "/")
	switch len(tokens) {
	case 2:
		return kubetypes.NamespacedName{Namespace: tokens[0], Name: tokens[1]}, nil
	case 1:
		return kubetypes.NamespacedName{Namespace: "default", Name: tokens[0]}, nil
	default:
		return kubetypes.NamespacedName{}, fmt.Errorf("invalid claim name: %s", s)
	}
}

type testLocalNodeSynchronizer struct{}

func (testLocalNodeSynchronizer) InitLocalNode(_ context.Context, n *node.LocalNode) error {
	n.Name = testLocalNodeName
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	n.Labels["kubernetes.io/hostname"] = testLocalNodeName
	return nil
}

func (testLocalNodeSynchronizer) SyncLocalNode(context.Context, *node.LocalNodeStore) {
}

func (testLocalNodeSynchronizer) WaitForNodeInformation(context.Context, *node.LocalNodeStore) error {
	return nil
}

var _ node.LocalNodeSynchronizer = testLocalNodeSynchronizer{}
