// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func testReconcilerScriptCommands(reconciler ConfigReconciler, instances map[string]*instance.BGPInstance) map[string]script.Cmd {
	return map[string]script.Cmd{
		"reconciler/init":      testReconcilerInitCmd(reconciler, instances),
		"reconciler/reconcile": testReconcilerReconcileCmd(reconciler, instances),
		"reconciler/cleanup":   testReconcilerCleanupCmd(reconciler, instances),
	}
}

func testReconcilerInitCmd(reconciler ConfigReconciler, instances map[string]*instance.BGPInstance) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "initialize new instance on the tested reconciler",
			Args:    "instance-name",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}
			i := &instance.BGPInstance{
				Name:   args[0],
				Router: fake.NewFakeRouter(),
			}
			instances[i.Name] = i
			return nil, reconciler.Init(i)
		},
	)
}

func testReconcilerReconcileCmd(reconciler ConfigReconciler, instances map[string]*instance.BGPInstance) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "call reconcile in the tested reconciler",
			Args:    "instance-name",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}
			i, ok := instances[args[0]]
			if !ok {
				return nil, fmt.Errorf("invalid instance name %s", args[0])
			}
			return nil, reconciler.Reconcile(s.Context(), ReconcileParams{
				BGPInstance:   i,
				DesiredConfig: &v2.CiliumBGPNodeInstance{Name: i.Name},
				CiliumNode:    &v2.CiliumNode{},
			})
		},
	)
}

func testReconcilerCleanupCmd(reconciler ConfigReconciler, instances map[string]*instance.BGPInstance) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "clean up instance on the tested reconciler",
			Args:    "instance-name",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}
			i, ok := instances[args[0]]
			if !ok {
				return nil, fmt.Errorf("invalid instance name %s", args[0])
			}
			reconciler.Cleanup(i)
			return nil, nil
		},
	)
}
