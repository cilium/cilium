// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"fmt"
	"maps"
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
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestScript(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	scripttest.Test(t,
		t.Context(),
		func(t testing.TB, args []string) *script.Engine {
			var (
				cs   *k8sClient.FakeClientset
				pods resource.Resource[*corev1.Pod]
			)

			h := hive.New(
				k8sClient.FakeClientCell(),
				k8s.ResourcesCell,
				cell.Provide(
					podResource,
					func() *option.DaemonConfig {
						return &option.DaemonConfig{}
					},
				),
				cell.Invoke(func(cs_ *k8sClient.FakeClientset, pods_ resource.Resource[*corev1.Pod]) {
					cs = cs_
					pods = pods_
				}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)
			log := hivetest.Logger(t)
			t.Cleanup(func() {
				// We cannot use t.Context() here because the context will be canceled
				// before h.Stop is called, causing goroutine leaks.
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				assert.NoError(t, h.Stop(log, ctx))
			})

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err)

			db := statedb.New()
			deviceTable, err := newDeviceTable(db)
			require.NoError(t, err)
			allocationTable, err := newAllocationTable(db)
			require.NoError(t, err)

			device := noSetupDummyDevice{&dummy.DummyDevice{Name: "test-device"}}
			txn := db.WriteTxn(deviceTable)
			_, _, err = deviceTable.Insert(txn, &DRADevice{
				Name:    device.IfName(),
				Manager: types.DeviceManagerTypeDummy,
				Dev:     device,
			})
			require.NoError(t, err)
			txn.Commit()

			driver := &Driver{
				logger:          log,
				kubeClient:      cs,
				pods:            pods,
				config:          &v2alpha1.CiliumNetworkDriverNodeConfigSpec{DriverName: "test.cilium.k8s.io"},
				db:              db,
				deviceTable:     deviceTable,
				allocationTable: allocationTable,
				ipv4Enabled:     true,
				ipv6Enabled:     true,
			}

			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			for _, cmd := range statedb.ScriptCommands(db).ScriptCmds {
				cmds[cmd.Name] = cmd.Cmd
			}
			maps.Insert(cmds, maps.All(scriptCommands(t.Context(), driver, cs)))
			return &script.Engine{Cmds: cmds}
		}, []string{}, "scripttest/testdata/static-addrs-in-claim.txtar")
}

func scriptCommands(ctx context.Context, driver *Driver, cs *k8sClient.FakeClientset) map[string]script.Cmd {
	return map[string]script.Cmd{
		"driver/prepare-resource-claims": script.Command(
			script.CmdUsage{
				Summary: "Call PrepareResourceClaims to prepare resources",
				Args:    "claims",
			},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				claims, err := scriptClaims(ctx, cs, args)
				if err != nil {
					return nil, err
				}
				results, err := driver.PrepareResourceClaims(ctx, claims)
				if err != nil {
					return nil, err
				}
				for _, claim := range claims {
					if result := results[claim.UID]; result.Err != nil {
						return nil, result.Err
					}
				}
				return nil, nil
			},
		),
		"driver/unprepare-resource-claims": script.Command(
			script.CmdUsage{Summary: "Call UnprepareResourceClaims to release resources", Args: "claims"},
			func(_ *script.State, args ...string) (script.WaitFunc, error) {
				claims, err := scriptClaims(ctx, cs, args)
				if err != nil {
					return nil, err
				}
				objects := make([]kubeletplugin.NamespacedObject, 0, len(claims))
				for _, claim := range claims {
					objects = append(objects, kubeletplugin.NamespacedObject{
						NamespacedName: kubetypes.NamespacedName{Namespace: claim.Namespace, Name: claim.Name},
						UID:            claim.UID,
					})
				}
				results, err := driver.UnprepareResourceClaims(ctx, objects)
				if err != nil {
					return nil, err
				}
				for _, obj := range objects {
					if result := results[obj.UID]; result != nil {
						return nil, result
					}
				}
				return nil, nil
			},
		),
	}
}

func scriptClaims(ctx context.Context, cs *k8sClient.FakeClientset, args []string) ([]*resourcev1.ResourceClaim, error) {
	if len(args) == 0 {
		return nil, script.ErrUsage
	}
	claims := make([]*resourcev1.ResourceClaim, 0, len(args))
	for _, arg := range args {
		parts := strings.Split(arg, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid claim name: %s", arg)
		}
		claim, err := cs.ResourceV1().ResourceClaims(parts[0]).Get(ctx, parts[1], metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

type noSetupDummyDevice struct {
	*dummy.DummyDevice
}

func (d noSetupDummyDevice) Setup(types.DeviceAllocation) (types.Device, error) { return d, nil }
func (noSetupDummyDevice) Free(types.DeviceAllocation) error                    { return nil }

var _ types.Device = noSetupDummyDevice{}
