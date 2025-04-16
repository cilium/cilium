// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"github.com/cilium/statedb"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	// Catch any leaked goroutines.
	t.Cleanup(func() { goleak.VerifyNone(t) })

	version.Force(testutils.DefaultVersion)
	setup := func(t testing.TB, args []string) *script.Engine {
		fakeEnvoy := &fakeEnvoySyncerAndPolicyTrigger{
			store: resourceStore{},
		}
		var lns *node.LocalNodeStore

		h := hive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			daemonk8s.TablesCell,
			maglev.Cell,
			cell.Config(cecConfig{}),
			cell.Config(envoy.ProxyConfig{}),

			lbcell.Cell,

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
				func() *loadbalancer.TestConfig {
					return &loadbalancer.TestConfig{}
				},
			),
			cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),

			cell.Module("cec-test", "test",
				// cecResourceParser and its friends.
				cell.Group(
					cell.Provide(
						newCECResourceParser,
						func(log *slog.Logger) PortAllocator { return staticPortAllocator{log} },
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

		var opts []hivetest.LogOption
		if *debug {
			opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		}
		log := hivetest.Logger(t, opts...)

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})
		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		cmds["envoy/cmp"] = script.Command(
			script.CmdUsage{
				Summary: "Compare Envoy resources",
				Args:    "file",
				Detail: []string{
					"The expected file is a simple sectioned text file with the format:",
					"section1:",
					"__section1_line1",
					"__section1_line2",
					"section2:",
					"__section2_line2",
					"",
					"Each section (except policy-trigger-count) is unmarshalled using",
					"prototext into a Envoy protobuf message and these are then compared",
					"using proto.Equal to the current resources.",
					"",
					"You are not supposed to maintain the expected file by hand, instead",
					"if the test case is new/changed you should run with '-scripttest.update'",
					"to update the expected file.",
					"",
					"For a new test case just add an empty file to the end of the txtar",
					"and run once with '-scripttest.update'.",
					"",
					"Do remember to verify the expected content carefully!",
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("expected filename")
				}
				b, err := os.ReadFile(s.Path(args[0]))
				if err != nil {
					return nil, fmt.Errorf("failed to read %q: %w", args[0], err)
				}

				if s.DoUpdate {
					// To avoid comparing too early when doing expected file updates
					// sleep a bit to make it much more likely that we'll get the
					// version we actually want.
					time.Sleep(500 * time.Millisecond)
				}

				expected, err := fakeEnvoy.compare(b)
				if err != nil && s.DoUpdate {
					// If -scripttest.update is set provide the expected output
					s.FileUpdates[args[0]] = expected
					return nil, nil
				}
				if err != nil {
					s.Logf("%s\n", err)
					diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
						A:        difflib.SplitLines(expected),
						FromFile: "<actual>",
						B:        difflib.SplitLines(string(b)),
						ToFile:   args[0],
						Context:  4,
					})
					s.Logf("%s\n", diff)
					s.Logf("(to update expected files run test again with -scripttest.update)\n")
				}
				return nil, err
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

type resourceKey struct {
	kind string // kind is listener/secret/etc.
	name string
}

func (k resourceKey) String() string {
	return k.kind + ":" + k.name
}

type resourceStore map[string]proto.Message

const (
	listenerKey  = "listener"
	secretKey    = "secret"
	routeKey     = "route"
	clustersKey  = "clusters"
	endpointsKey = "endpoints"
)

func (rs resourceStore) equal(other resourceStore) bool {
	return maps.EqualFunc(rs, other, proto.Equal)
}

func (rs resourceStore) update(res *envoy.Resources) {
	for _, l := range res.Listeners {
		rs[resourceKey{kind: listenerKey, name: l.Name}.String()] = l
	}
	for _, s := range res.Secrets {
		rs[resourceKey{kind: secretKey, name: s.Name}.String()] = s
	}
	for _, r := range res.Routes {
		rs[resourceKey{kind: routeKey, name: r.Name}.String()] = r
	}
	for _, c := range res.Clusters {
		rs[resourceKey{kind: clustersKey, name: c.Name}.String()] = c
	}
	for _, e := range res.Endpoints {
		rs[resourceKey{kind: endpointsKey, name: e.ClusterName}.String()] = e
	}
}

func (rs resourceStore) delete(res *envoy.Resources) {
	for _, l := range res.Listeners {
		delete(rs, resourceKey{kind: listenerKey, name: l.Name}.String())
	}
	for _, s := range res.Secrets {
		delete(rs, resourceKey{kind: secretKey, name: s.Name}.String())
	}
	for _, r := range res.Routes {
		delete(rs, resourceKey{kind: routeKey, name: r.Name}.String())
	}
	for _, c := range res.Clusters {
		delete(rs, resourceKey{kind: clustersKey, name: c.Name}.String())
	}
	for _, e := range res.Endpoints {
		delete(rs, resourceKey{kind: endpointsKey, name: e.ClusterName}.String())
	}
}

type fakeEnvoySyncerAndPolicyTrigger struct {
	lock.Mutex
	store              resourceStore
	policyTriggerCount int
}

type section struct {
	name    string
	content []byte
}

func (s section) String() string {
	return fmt.Sprintf("%s: %q", s.name, s.content)
}

// parseSections parses a file formatted into indented sections:
//
//	section1:
//	  s1line1
//	  s1line2
//	section2:
//	  s2line1
//
// This returns: [{"section1", "s1line1\ns1line2"}, "section2", "s2line1\n"}]
func parseSections(b []byte) (sections []section, err error) {
	var currentName string
	var contentBuilder bytes.Buffer
	for line := range bytes.SplitSeq(b, []byte{'\n'}) {
		switch {
		case len(line) == 0:
			contentBuilder.WriteRune('\n')
		case line[0] == ' ':
			if line[1] != ' ' {
				return nil, fmt.Errorf("bad section format, expected double space on line: %q", line)
			}
			contentBuilder.Write(line[2:])
			contentBuilder.WriteRune('\n')
		default:
			if currentName != "" {
				sections = append(sections, section{currentName, contentBuilder.Bytes()})
				contentBuilder = bytes.Buffer{}
			}
			currentName, _ = strings.CutSuffix(string(line), ":")
		}
	}
	if currentName != "" {
		sections = append(sections, section{currentName, contentBuilder.Bytes()})
	}
	return sections, nil
}

func sectionToMessage(sectionName string) proto.Message {
	switch {
	case strings.HasPrefix(sectionName, listenerKey):
		return &envoy_config_listener.Listener{}
	case strings.HasPrefix(sectionName, secretKey):
		return &envoy_config_tls.Secret{}
	case strings.HasPrefix(sectionName, routeKey):
		return &envoy_config_route.RouteConfiguration{}
	case strings.HasPrefix(sectionName, clustersKey):
		return &envoy_config_cluster.Cluster{}
	case strings.HasPrefix(sectionName, endpointsKey):
		return &envoy_config_endpoint.ClusterLoadAssignment{}
	default:
		return nil
	}
}

func (f *fakeEnvoySyncerAndPolicyTrigger) compare(b []byte) (expected string, err error) {
	f.Lock()
	defer f.Unlock()

	expected = f.summary()

	resources := resourceStore{}
	sections, err := parseSections(b)
	if err != nil {
		return expected, err
	}

	triggerCount := 0

	for _, section := range sections {
		if strings.HasPrefix("policy-trigger-count", section.name) {
			if c, err := strconv.ParseInt(strings.TrimSpace(string(section.content)), 10, 64); err == nil {
				triggerCount = int(c)
			} else {
				return expected, err
			}
			continue
		}
		msg := sectionToMessage(section.name)
		if msg == nil {
			err = fmt.Errorf("unhandled section %s", section.name)
			return
		}
		if err = prototext.Unmarshal(section.content, msg); err != nil {
			err = fmt.Errorf("unmarshaling %q failed: %w", section.name, err)
			return
		}
		resources[section.name] = msg
	}

	// Compare the resources using proto.Equal. This way we do not rely on stability of prototext
	// (it inserts spaces randomly to stop this sort of thing).
	if triggerCount != f.policyTriggerCount || !resources.equal(f.store) {
		// The resources are not equal, return the expected output.
		return expected, errors.New("resources not equal")
	}
	return expected, nil
}

func (f *fakeEnvoySyncerAndPolicyTrigger) summary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "policy-trigger-count:\n  %d\n", f.policyTriggerCount)

	for _, k := range slices.Sorted(maps.Keys(f.store)) {
		v := f.store[k]
		fmt.Fprintf(&b, "%s:\n  %s\n", k, indentLines(prototext.Format(v)))
	}
	return b.String()
}

func indentLines(s string) string {
	return strings.ReplaceAll(s, "\n", "\n  ")
}

// DeleteResources implements envoySyncer.
func (f *fakeEnvoySyncerAndPolicyTrigger) DeleteEnvoyResources(ctx context.Context, res envoy.Resources) error {
	f.Lock()
	defer f.Unlock()
	f.store.delete(&res)

	for _, listener := range res.Listeners {
		if cb := res.PortAllocationCallbacks[listener.Name]; cb != nil {
			cb(ctx)
		}
	}
	return nil
}

// UpdateResources implements envoySyncer.
func (f *fakeEnvoySyncerAndPolicyTrigger) UpdateEnvoyResources(ctx context.Context, old envoy.Resources, new envoy.Resources) error {
	f.Lock()
	defer f.Unlock()
	f.store.delete(&old)
	f.store.update(&new)

	for _, oldListener := range old.Listeners {
		for _, newListener := range new.Listeners {
			if newListener.Name == oldListener.Name {
				delete(new.PortAllocationCallbacks, newListener.Name)
			}
		}
	}

	for _, listener := range new.Listeners {
		if cb := new.PortAllocationCallbacks[listener.Name]; cb != nil {
			cb(ctx)
		}
	}

	return nil
}

var _ resourceMutator = &fakeEnvoySyncerAndPolicyTrigger{}

// TriggerPolicyUpdates implements policyTrigger.
func (f *fakeEnvoySyncerAndPolicyTrigger) TriggerPolicyUpdates() {
	f.Lock()
	defer f.Unlock()
	f.policyTriggerCount++
}

var _ policyTrigger = &fakeEnvoySyncerAndPolicyTrigger{}

type staticPortAllocator struct {
	log *slog.Logger
}

// AckProxyPort implements PortAllocator.
func (s staticPortAllocator) AckProxyPort(ctx context.Context, name string) error {
	s.log.Info("AckProxyPort", logfields.Listener, name)
	return nil
}

// AllocateCRDProxyPort implements PortAllocator.
func (s staticPortAllocator) AllocateCRDProxyPort(name string) (uint16, error) {
	return 1000, nil
}

// ReleaseProxyPort implements PortAllocator.
func (s staticPortAllocator) ReleaseProxyPort(name string) error {
	s.log.Info("ReleaseProxyPort", logfields.Listener, name)
	return nil
}

var _ PortAllocator = staticPortAllocator{}
