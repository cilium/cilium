// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestControllerRuntimeScriptCommands(t *testing.T) {
	setup := func(t testing.TB, _ []string) *script.Engine {
		scheme := runtime.NewScheme()
		if err := corev1.AddToScheme(scheme); err != nil {
			t.Fatal(err)
		}
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		cmds := ControllerRuntimeScriptCommands(c,
			map[string]reconcile.Reconciler{"configmap": reconcile.Func(func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
				var cm corev1.ConfigMap
				if err := c.Get(ctx, req.NamespacedName, &cm); err != nil {
					return ctrl.Result{}, err
				}
				cm.Data = map[string]string{"reconciled": "true"}
				return ctrl.Result{}, c.Update(ctx, &cm)
			})},
		)
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		return &script.Engine{Cmds: cmds}
	}
	scripttest.Test(t, t.Context(), setup, nil, "testdata/controller-runtime-script.txtar")
}
