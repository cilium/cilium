// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func TestScript(t *testing.T) {
	// Catch any leaked goroutines.
	t.Cleanup(func() { goleak.VerifyNone(t) })

	version.Force(testutils.DefaultVersion)
	setup := func(t testing.TB, args []string) *script.Engine {
		fakeEnvoy := &fakeEnvoySyncerAndPolicyTrigger{}
		var lns *node.LocalNodeStore

		h := hive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			daemonk8s.TablesCell,
			cell.Config(cecConfig{}),
			cell.Config(envoy.ProxyConfig{}),
			experimental.Cell,
			maglev.Cell,
			cell.Provide(
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				source.NewSources,
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableIPv4:           true,
						EnableIPv6:           true,
						EnableNodePort:       true,
						SockRevNatEntries:    1000,
						LBMapEntries:         1000,
						EnableL7Proxy:        true,
						EnableEnvoyConfig:    true,
						KubeProxyReplacement: option.KubeProxyReplacementTrue,
					}
				},
				func() *experimental.TestConfig {
					return &experimental.TestConfig{}
				},
			),
			cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),

			cell.Module("cec-test", "test",
				// cecResourceParser and its friends.
				cell.Group(
					cell.Provide(
						newCECResourceParser,
						func() PortAllocator { return staticPortAllocator{} },
					),
					node.LocalNodeStoreCell,
					cell.Invoke(func(lns_ *node.LocalNodeStore) { lns = lns_ }),
				),
				experimentalTableCells,
				experimentalControllerCells,

				cell.ProvidePrivate(
					func() promise.Promise[synced.CRDSync] {
						r, p := promise.New[synced.CRDSync]()
						r.Resolve(synced.CRDSync{})
						return p
					},
					func() resourceMutator { return fakeEnvoy },
					func() policyTrigger { return fakeEnvoy },
				),
			),
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		flags.Set("enable-experimental-lb", "true")

		log := hivetest.Logger(t)
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})
		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		cmds["envoy"] = script.Command(
			script.CmdUsage{Summary: "Show last Envoy resources", Args: "file"},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("expected output filename")
				}
				f, err := os.OpenFile(s.Path(args[0]), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					return nil, err
				}
				defer f.Close()
				_, err = fmt.Fprintf(f, "policy-trigger-count: %d\n", fakeEnvoy.policyTriggerCount.Load())
				if err != nil {
					return nil, err
				}
				for _, info := range fakeEnvoy.all() {
					if info.res == nil {
						_, err = fmt.Fprintf(f, "%s: listeners=<nil> endpoints=<nil>\n", info.name)
						if err != nil {
							return nil, err
						}
						continue
					}
					var listeners, endpoints []string
					for _, l := range info.res.Listeners {
						listeners = append(listeners,
							fmt.Sprintf("%s/%d", l.Name, l.Address.GetSocketAddress().GetPortValue()))
					}
					sort.Strings(listeners)
					for _, cla := range info.res.Endpoints {
						for _, eps := range cla.Endpoints {
							backends := make([]string, 0, len(eps.LbEndpoints))
							for _, lep := range eps.LbEndpoints {
								ep := lep.GetEndpoint()
								sa := ep.Address.GetSocketAddress()
								backends = append(backends, fmt.Sprintf("%s:%d", sa.Address, sa.GetPortValue()))
							}
							endpoints = append(endpoints, cla.ClusterName+"="+strings.Join(backends, ","))
						}
					}
					sort.Strings(endpoints)
					_, err = fmt.Fprintf(f, "%s: listeners=%s endpoints=%s\n", info.name, strings.Join(listeners, ","), strings.Join(endpoints, ","))
					if err != nil {
						return nil, err
					}
				}
				return nil, nil
			},
		)
		cmds["set-node-labels"] = script.Command(
			script.CmdUsage{Summary: "Set local node labels", Args: "key=value..."},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				labels := map[string]string{}
				for _, arg := range args {
					key, value, found := strings.Cut(arg, "=")
					if !found {
						return nil, fmt.Errorf("bad key=value: %q", arg)
					}
					labels[key] = value
				}
				lns.Update(func(n *node.LocalNode) {
					n.Labels = labels
					s.Logf("Labels set to %v\n", labels)
				})
				return nil, nil
			})

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    100 * time.Millisecond,
			MaxRetryInterval: time.Second,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{},
		"testdata/*.txtar")

}

type resourceStore struct {
	count atomic.Int32
	res   atomic.Pointer[envoy.Resources]
}

func (r *resourceStore) incr(res *envoy.Resources) {
	r.count.Add(1)
	r.res.Store(res)
}

type fakeEnvoySyncerAndPolicyTrigger struct {
	update, delete     resourceStore
	policyTriggerCount atomic.Int32
}

type resourceInfo struct {
	name  string
	count int32
	res   *envoy.Resources
}

func (f *fakeEnvoySyncerAndPolicyTrigger) all() []resourceInfo {
	return []resourceInfo{
		{"update", f.update.count.Load(), f.update.res.Load()},
		{"delete", f.delete.count.Load(), f.delete.res.Load()},
	}
}

// DeleteResources implements envoySyncer.
func (f *fakeEnvoySyncerAndPolicyTrigger) DeleteEnvoyResources(ctx context.Context, res envoy.Resources) error {
	f.delete.incr(&res)
	return nil
}

// UpdateResources implements envoySyncer.
func (f *fakeEnvoySyncerAndPolicyTrigger) UpdateEnvoyResources(ctx context.Context, old envoy.Resources, new envoy.Resources) error {
	f.update.incr(&new)
	return nil
}

var _ resourceMutator = &fakeEnvoySyncerAndPolicyTrigger{}

// TriggerPolicyUpdates implements policyTrigger.
func (f *fakeEnvoySyncerAndPolicyTrigger) TriggerPolicyUpdates() {
	f.policyTriggerCount.Add(1)
}

var _ policyTrigger = &fakeEnvoySyncerAndPolicyTrigger{}

type staticPortAllocator struct{}

// AckProxyPort implements PortAllocator.
func (s staticPortAllocator) AckProxyPort(ctx context.Context, name string) error {
	return nil
}

// AllocateCRDProxyPort implements PortAllocator.
func (s staticPortAllocator) AllocateCRDProxyPort(name string) (uint16, error) {
	return 1000, nil
}

// ReleaseProxyPort implements PortAllocator.
func (s staticPortAllocator) ReleaseProxyPort(name string) error {
	return nil
}

var _ PortAllocator = staticPortAllocator{}
