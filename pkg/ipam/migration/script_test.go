// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package migration

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
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

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	sysctlFake "github.com/cilium/cilium/pkg/datapath/linux/sysctl/fake"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	ipamcell "github.com/cilium/cilium/pkg/ipam/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipmasq"
	k8sClientTest "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/mtu"
	mtuFake "github.com/cilium/cilium/pkg/mtu/fake"
	"github.com/cilium/cilium/pkg/node"
	nodeFake "github.com/cilium/cilium/pkg/node/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestScriptClusterPoolToMultiPool(t *testing.T) {
	var (
		initializer *ipamcell.IPAMInitializer
		manager     *ipam.IPAM
	)

	defer testutils.GoleakVerifyNone(t)

	scripttest.Test(t,
		t.Context(),
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				k8sClientTest.FakeClientCell(),
				agentK8s.ResourcesCell,
				k8sTables.TablesCell,
				datapathTables.DirectRoutingDeviceCell,
				cell.Provide(
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4:                 true,
							EnableIPv6:                 true,
							EnableCiliumNodeCRD:        true,
							IPAM:                       ipamOption.IPAMMultiPool,
							IPAMDefaultIPPool:          defaults.IPAMDefaultIPPool,
							IPAMMultiPoolPreAllocation: map[string]string{defaults.IPAMDefaultIPPool: "8"},
							IPAMCiliumNodeUpdateRate:   time.Nanosecond, // speed up CiliumNode sync to k8s
							IPv4Range:                  "auto",
							IPv6Range:                  "auto",
						}
					},
					func() *node.LocalNodeStore {
						nodeTypes.SetName("test-node")
						localNode := node.LocalNode{
							Node: nodeTypes.Node{
								Name:          nodeTypes.GetName(),
								IPv4AllocCIDR: cidr.MustParseCIDR("10.244.0.0/24"),
								IPv6AllocCIDR: cidr.MustParseCIDR("fd00:10:244::/96"),
							},
							Local: &node.LocalNodeInfo{},
						}
						return node.NewTestLocalNodeStore(localNode)
					},
					func() node.Addressing { return nodeFake.NewAddressing() },
					func() *watchers.K8sEventReporter { return &watchers.K8sEventReporter{} },
					func() endpointmanager.EndpointManager { return noopEndpointManager{} },
					func() *nodediscovery.NodeDiscovery { return &nodediscovery.NodeDiscovery{} },
					func() *ipmasq.IPMasqAgent { return nil },
					func() mtu.MTU { return &mtuFake.MTU{} },
					func() sysctl.Sysctl { return &sysctlFake.Sysctl{} },
					datapathTables.NewDeviceTable,
					statedb.RWTable[*datapathTables.Device].ToTable,
				),

				ipamcell.Cell,

				cell.Invoke(func(initializer_ *ipamcell.IPAMInitializer, manager_ *ipam.IPAM) {
					initializer = initializer_
					manager = manager_
				}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			maps.Insert(cmds, maps.All(commands(initializer, manager)))

			return &script.Engine{Cmds: cmds}
		}, []string{}, "testdata/*.txtar")
}

func commands(initializer *ipamcell.IPAMInitializer, manager *ipam.IPAM) map[string]script.Cmd {
	return map[string]script.Cmd{
		"ipam/start": script.Command(
			script.CmdUsage{
				Summary: "Call IPAMInitializer.ConfigureAndStartIPAM",
			},
			func(state *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 0 {
					return nil, script.ErrUsage
				}
				initializer.ConfigureAndStartIPAM(state.Context())
				return nil, nil
			},
		),
		"ipam/restore-endpoint": script.Command(
			script.CmdUsage{
				Summary: "Restore an endpoint IP allocation through IPAM",
				Args:    "ip-address owner",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 2 {
					return nil, script.ErrUsage
				}

				addr, err := netip.ParseAddr(args[0])
				if err != nil {
					return nil, err
				}

				_, err = manager.AllocateIPWithoutSyncUpstream(
					addr.AsSlice(),
					args[1],
					ipam.PoolOrDefault(""), // restored endpoints from cluster-pool should have an empty pool
				)
				return nil, err
			},
		),
		"ipam/restore-finished": script.Command(
			script.CmdUsage{
				Summary: "Call IPAMInitializer.RestoreFinished",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 0 {
					return nil, script.ErrUsage
				}
				initializer.RestoreFinished()
				return nil, nil
			},
		),
		"ipam/allocate": script.Command(
			script.CmdUsage{
				Summary: "Allocate the next pod IPs from the default pool",
				Args:    "owner",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, script.ErrUsage
				}

				_, _, err := manager.AllocateNext("", args[0], ipam.PoolDefault())
				return nil, err
			},
		),
		"ipam/dump": script.Command(
			script.CmdUsage{
				Summary: "Write formatted IPAM.Dump output to a file",
				Args:    "output-file",
			},
			func(state *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, script.ErrUsage
				}

				allocv4, allocv6, _ := manager.Dump()
				data, err := formatDump(allocv4, allocv6)
				if err != nil {
					return nil, err
				}

				return nil, os.WriteFile(state.Path(args[0]), []byte(data), 0644)
			},
		),
	}
}

type ipamStatus struct {
	IPv4 ipamAllocs `json:"ipv4"`
	IPv6 ipamAllocs `json:"ipv6"`
}

type ipamAllocs struct {
	Pools  map[string]int `json:"pools"`
	Owners []string       `json:"owners"`
}

func formatDump(allocv4, allocv6 map[string]string) (string, error) {
	dump := ipamStatus{
		IPv4: formatAllocs(allocv4),
		IPv6: formatAllocs(allocv6),
	}

	out, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

func formatAllocs(allocs map[string]string) ipamAllocs {
	family := ipamAllocs{
		Pools:  map[string]int{},
		Owners: make([]string, 0, len(allocs)),
	}

	for ip, owner := range allocs {
		pool, _, ok := strings.Cut(ip, "/")
		if !ok {
			pool = string(ipam.PoolDefault())
		}
		family.Pools[pool]++

		family.Owners = append(family.Owners, owner)
	}
	sort.Strings(family.Owners)

	return family
}

type noopEndpointManager struct{}

func (noopEndpointManager) Lookup(string) (*endpoint.Endpoint, error) { return nil, nil }
func (noopEndpointManager) LookupCiliumID(uint16) *endpoint.Endpoint  { return nil }
func (noopEndpointManager) LookupCNIAttachmentID(string) *endpoint.Endpoint {
	return nil
}
func (noopEndpointManager) LookupIPv4(string) *endpoint.Endpoint { return nil }
func (noopEndpointManager) LookupIPv6(string) *endpoint.Endpoint { return nil }
func (noopEndpointManager) LookupIP(netip.Addr) *endpoint.Endpoint {
	return nil
}
func (noopEndpointManager) LookupCEPName(string) *endpoint.Endpoint { return nil }
func (noopEndpointManager) GetEndpointsByPodName(string) []*endpoint.Endpoint {
	return nil
}
func (noopEndpointManager) GetEndpointsByContainerID(string) []*endpoint.Endpoint {
	return nil
}
func (noopEndpointManager) GetEndpointsByServiceAccount(string, string) []*endpoint.Endpoint {
	return nil
}
func (noopEndpointManager) GetEndpointsByNamespace(string) []*endpoint.Endpoint {
	return nil
}
func (noopEndpointManager) GetEndpoints() []*endpoint.Endpoint { return nil }
func (noopEndpointManager) GetEndpointList(endpointapi.GetEndpointParams) []*models.Endpoint {
	return nil
}
func (noopEndpointManager) EndpointExists(uint16) bool             { return false }
func (noopEndpointManager) GetHostEndpoint() *endpoint.Endpoint    { return nil }
func (noopEndpointManager) HostEndpointExists() bool               { return false }
func (noopEndpointManager) GetIngressEndpoint() *endpoint.Endpoint { return nil }
func (noopEndpointManager) IngressEndpointExists() bool            { return false }
func (noopEndpointManager) AddEndpoint(*endpoint.Endpoint) error   { return nil }
func (noopEndpointManager) RestoreEndpoint(*endpoint.Endpoint) error {
	return nil
}
func (noopEndpointManager) UpdateReferences(*endpoint.Endpoint) error {
	return nil
}
func (noopEndpointManager) RemoveEndpoint(*endpoint.Endpoint, endpoint.DeleteConfig) []error {
	return nil
}
func (noopEndpointManager) RunK8sCiliumEndpointSync(*endpoint.Endpoint, cell.Health) {}
func (noopEndpointManager) DeleteK8sCiliumEndpointSync(*endpoint.Endpoint)           {}
func (noopEndpointManager) Subscribe(endpointmanager.Subscriber)                     {}
func (noopEndpointManager) Unsubscribe(endpointmanager.Subscriber)                   {}
func (noopEndpointManager) UpdatePolicyMaps(context.Context) error                   { return nil }
func (noopEndpointManager) RegenerateAllEndpoints(*regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	return &sync.WaitGroup{}
}
func (noopEndpointManager) TriggerRegenerateAllEndpoints()                            {}
func (noopEndpointManager) RegenerateAllForPolicy(uint64)                             {}
func (noopEndpointManager) WaitForEndpointsAtPolicyRev(context.Context, uint64) error { return nil }
func (noopEndpointManager) OverrideEndpointOpts(option.OptionMap)                     {}
func (noopEndpointManager) InitHostEndpointLabels(context.Context)                    {}
func (noopEndpointManager) UpdatePolicy(*set.Set[identity.NumericIdentity], uint64, uint64) {
}

var _ endpointmanager.EndpointManager = noopEndpointManager{}
