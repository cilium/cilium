// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"maps"
	"net"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	k8sFake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"
)

func TestPrivilegedScripts(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)
	ctx := t.Context()

	// Set the node name to be "localnode1" for all the tests.
	nodeTypes.SetName("localnode1")

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				k8sFake.FakeClientCell(),
				daemonk8s.ResourcesCell,
				k8sTables.NamespaceTableCell,
				agent.Cell,

				Cell,
				sysctl.Cell,

				// Note: We use the default local node store, and setup the node obj
				// using the mock node sync type.
				node.LocalNodeStoreCell,
				endpointmanager.Cell,
				cell.Provide(func() promise.Promise[endpointstate.Restorer] {
					resolver, promise := promise.New[endpointstate.Restorer]()
					resolver.Resolve(&fakeRestorer{})
					return promise
				}),
				tunnel.Cell,

				testCell,

				cell.Config(metrics.RegistryConfig{}),
				cell.Config(cmtypes.DefaultClusterInfo),
				cell.Provide(
					metrics.NewRegistry,
					// LocalNodeSynchronizer syncs via apiserver, after the node is initialized, generally
					// using local stored config (if available) in daemon package.
					func() node.LocalNodeSynchronizer {
						return &mockNodeSync{}
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4:             true,
							EnableIPv6:             true,
							EnableBPFMasquerade:    true,
							EnableIPv4Masquerade:   true,
							EnableIPv6Masquerade:   true,
							EnableEgressGateway:    true,
							IdentityAllocationMode: option.IdentityAllocationModeCRD,
							Debug:                  false,
						}
					},

					func() cache.IdentityAllocator {
						m := testidentity.NewMockIdentityAllocator(nil)

						_, _, err := m.AllocateIdentity(context.TODO(),
							labels.NewLabelsFromSortedList("k8s:foo=bar"),
							false,
							30000,
						)
						assert.NoError(t, err)

						return m
					},

					tables.NewDeviceTable,
					statedb.RWTable[*tables.Device].ToTable,
					statedb.RWTable[tables.NodeAddress].ToTable,

					func() loadbalancer.Config {
						return loadbalancer.DefaultConfig
					},
				),

				cell.Invoke(func(*Manager) {}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 1500 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}

var testCell = cell.Group(
	testCommandsCell,
	cell.Provide(
		func() egressmap.PolicyConfig {
			return egressmap.DefaultPolicyConfig
		},
		egressmap.CreatePrivatePolicyMap4,
		egressmap.CreatePrivatePolicyMap4V2,
		egressmap.CreatePrivatePolicyMap6,
	),
)

type mockNodeSync struct{}

func (m *mockNodeSync) WaitForNodeInformation(ctx context.Context, store *node.LocalNodeStore) error {
	return nil
}

func (m *mockNodeSync) InitLocalNode(ctx context.Context, n *node.LocalNode) error {
	n.Node = nodeTypes.Node{
		Name: "localnode1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("172.18.0.3")},
		},
	}
	return nil
}

func (m *mockNodeSync) SyncLocalNode(context.Context, *node.LocalNodeStore) {
}

type fakeRestorer struct{}

func (r *fakeRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return r, nil
}

func (r *fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return nil
}

func (r *fakeRestorer) WaitForEndpointRestore(_ context.Context) error {
	return nil
}

func (r *fakeRestorer) WaitForInitialPolicy(_ context.Context) error {
	return nil
}
