// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/time"
)

// TestScript runs all the testdata/*.txtar script tests. The tests are
// run in parallel. If you need to update the expected files inside the txtar
// files you can run 'go test . -scripttest.update' to update the files.
func TestScript(t *testing.T) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				FakeClientCell(),

				// Also add an object through the clientset interface to check that it can be seen and retrieved
				// using the k8s commands.
				cell.Invoke(func(cs *FakeClientset) error {
					_, err := cs.CiliumFakeClientset.CiliumV2().CiliumNodes().Create(
						ctx,
						&v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{Name: "test"},
						},
						metav1.CreateOptions{},
					)
					return err
				}),

				cell.Provide(func(cs *FakeClientset) uhive.ScriptCmdOut {
					return uhive.NewScriptCmd("k8s/svc/update-status", script.Command(
						script.CmdUsage{
							Summary: "Invoke [Services.UpdateStatus]",
							Args:    "file",
						},
						func(s *script.State, args ...string) (script.WaitFunc, error) {
							if len(args) != 1 {
								return nil, script.ErrUsage
							}

							obj, err := testutils.DecodeFile(s.Path(args[0]))
							if err != nil {
								return nil, fmt.Errorf("reading %s: %w", args[0], err)
							}

							svc, ok := obj.(*slimcorev1.Service)
							if !ok {
								return nil, fmt.Errorf("reading %s: not a slim service (%T)", args[0], svc)
							}

							_, err = cs.SlimFakeClientset.CoreV1().Services(svc.Namespace).
								UpdateStatus(s.Context(), svc, metav1.UpdateOptions{})
							return nil, err
						},
					))
				}),
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
				Cmds: cmds,
			}
		}, []string{}, "testdata/*.txtar")
}
