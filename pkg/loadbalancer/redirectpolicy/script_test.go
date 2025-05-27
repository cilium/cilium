// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy_test

import (
	"context"
	"flag"
	"iter"
	"log/slog"
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
	"go.uber.org/goleak"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	defer goleak.VerifyNone(t)

	version.Force(k8sTestutils.DefaultVersion)
	nodeTypes.SetName("testnode")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			log := hivetest.Logger(t, opts...)
			h := hive.New(
				client.FakeClientCell,
				daemonk8s.ResourcesCell,
				daemonk8s.TablesCell,
				metrics.Cell,

				lbcell.Cell,

				node.LocalNodeStoreCell,
				maglev.Cell,
				cell.Provide(
					source.NewSources,
					func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4:                true,
							EnableIPv6:                true,
							EnableNodePort:            true,
							EnableLocalRedirectPolicy: true,
							KubeProxyReplacement:      option.KubeProxyReplacementTrue,
						}
					},
					func() redirectpolicy.TestSkipLBMap {
						// Only use fake SkipLBMap if we're running unprivileged tests.
						if testutils.IsPrivileged() {
							return nil
						}
						return &fakeSkipLBMap{}
					},
				),
				cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Set some defaults
			flags.Set("enable-experimental-lb", "true")
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}

type fakeSkipLBMap struct {
	entries lock.Map[any, any]
}

// OpenOrCreate implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) OpenOrCreate() error {
	return nil
}

// Close implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) Close() error {
	return nil
}

// AddLB4 implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) AddLB4(netnsCookie uint64, ip net.IP, port uint16) error {
	key := lbmap.SkipLB4Key{
		NetnsCookie: netnsCookie,
		Address:     ([4]byte)(ip),
		Port:        port,
	}
	f.entries.Store(
		key,
		&lbmap.SkipLB4Value{},
	)
	return nil
}

// AddLB6 implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) AddLB6(netnsCookie uint64, ip net.IP, port uint16) error {
	key := lbmap.SkipLB6Key{
		NetnsCookie: netnsCookie,
		Address:     ([16]byte)(ip),
		Port:        port,
	}
	f.entries.Store(
		key,
		&lbmap.SkipLB6Value{},
	)
	return nil
}

// AllLB4 implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) AllLB4() iter.Seq2[*lbmap.SkipLB4Key, *lbmap.SkipLB4Value] {
	return func(yield func(*lbmap.SkipLB4Key, *lbmap.SkipLB4Value) bool) {
		f.entries.Range(func(key any, value any) bool {
			switch key := key.(type) {
			case lbmap.SkipLB4Key:
				if !yield(&key, value.(*lbmap.SkipLB4Value)) {
					return false
				}
			}
			return true
		})
	}
}

// AllLB6 implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) AllLB6() iter.Seq2[*lbmap.SkipLB6Key, *lbmap.SkipLB6Value] {
	return func(yield func(*lbmap.SkipLB6Key, *lbmap.SkipLB6Value) bool) {
		f.entries.Range(func(key any, value any) bool {
			switch key := key.(type) {
			case lbmap.SkipLB6Key:
				if !yield(&key, value.(*lbmap.SkipLB6Value)) {
					return false
				}
			}
			return true
		})
	}
}

// DeleteLB4 implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) DeleteLB4(key *lbmap.SkipLB4Key) error {
	f.entries.Delete(*key)
	return nil
}

// DeleteLB4ByAddrPort implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) DeleteLB4ByAddrPort(ip net.IP, port uint16) {
	panic("unimplemented")
}

// DeleteLB4ByNetnsCookie implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) DeleteLB4ByNetnsCookie(cookie uint64) {
	panic("unimplemented")
}

// DeleteLB6 implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) DeleteLB6(key *lbmap.SkipLB6Key) error {
	f.entries.Delete(*key)
	return nil
}

// DeleteLB6ByAddrPort implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) DeleteLB6ByAddrPort(ip net.IP, port uint16) {
	panic("unimplemented")
}

// DeleteLB6ByNetnsCookie implements lbmap.SkipLBMap.
func (f *fakeSkipLBMap) DeleteLB6ByNetnsCookie(cookie uint64) {
	panic("unimplemented")
}

var _ lbmap.SkipLBMap = &fakeSkipLBMap{}
