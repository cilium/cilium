// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway_test

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"
)

func TestScript(t *testing.T) {
	log := hivetest.Logger(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// Set the node name to be "node1" for all the tests.
	nodeTypes.SetName("node1")

	logging.SetLogLevelToDebug()
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				client.FakeClientCell,
				daemonk8s.ResourcesCell,
				egressgateway.Cell,
				node.LocalNodeStoreCell,

				cell.Provide(
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4EgressGateway: true,
							EnableBPFMasquerade:     true,
							EnableIPv4Masquerade:    true,
							IdentityAllocationMode:  option.IdentityAllocationModeCRD,
						}
					},
					func() cache.IdentityAllocator {
						m := testidentity.NewMockIdentityAllocator(nil)
						// Pre-allocate some endpoint identities. These start from 1000.
						// TODO: Preferably we wouldn't need to mock and we could pull
						// in the real identity allocator that would be fed from CiliumEndpoint.
						m.AllocateIdentity(context.TODO(),
							labels.NewLabelsFromSortedList("k8s:org=empire"),
							false,
							0,
						)
						return m
					},
					func() sysctl.Sysctl {
						return sysctl.NoopSysctl{}
					},
					func() (egressmap.PolicyMap, uhive.ScriptCmdOut) {
						ipm := &inmemPolicyMap{}
						return ipm, uhive.NewScriptCmd("egressmap/dump",
							script.Command(
								script.CmdUsage{Summary: "Dump in-memory egressmap to stdout"},
								ipm.dumpCommand))
					},
				),

				cell.Invoke(func(*egressgateway.Manager) {}),
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
				Cmds:             cmds,
				RetryInterval:    100 * time.Millisecond,
				MaxRetryInterval: time.Second,
			}
		}, []string{}, "testdata/*.txtar")
}

type inmemPolicyMap struct {
	m lock.Map[egressmap.EgressPolicyKey4, egressmap.EgressPolicyVal4]
}

func (i *inmemPolicyMap) dumpCommand(_ *script.State, args ...string) (script.WaitFunc, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("%w: expected output filename", script.ErrUsage)
	}

	return func(s *script.State) (stdout, stderr string, err error) {
		f, err := os.OpenFile(s.Path(args[0]), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return "", "", err
		}
		defer f.Close()
		i.m.Range(func(key egressmap.EgressPolicyKey4, value egressmap.EgressPolicyVal4) bool {
			fmt.Fprintf(f, "%s: %s\n", key.String(), value.String())
			return true
		})
		return
	}, nil
}

// Delete implements egressmap.PolicyMap.
func (i *inmemPolicyMap) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	i.m.Delete(egressmap.NewEgressPolicyKey4(sourceIP, destCIDR))
	return nil
}

// IterateWithCallback implements egressmap.PolicyMap.
func (i *inmemPolicyMap) IterateWithCallback(cb egressmap.EgressPolicyIterateCallback) error {
	i.m.Range(func(key egressmap.EgressPolicyKey4, value egressmap.EgressPolicyVal4) bool {
		cb(&key, &value)
		return true
	})
	return nil
}

// Lookup implements egressmap.PolicyMap.
func (i *inmemPolicyMap) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*egressmap.EgressPolicyVal4, error) {
	v, found := i.m.Load(egressmap.NewEgressPolicyKey4(sourceIP, destCIDR))
	if !found {
		return nil, ebpf.ErrKeyNotExist
	}
	return &v, nil
}

// Update implements egressmap.PolicyMap.
func (i *inmemPolicyMap) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIP netip.Addr) error {
	i.m.Store(
		egressmap.NewEgressPolicyKey4(sourceIP, destCIDR),
		egressmap.NewEgressPolicyVal4(egressIP, gatewayIP),
	)
	return nil
}

var _ egressmap.PolicyMap = &inmemPolicyMap{}
