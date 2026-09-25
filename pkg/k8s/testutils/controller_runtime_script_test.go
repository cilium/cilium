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
	"k8s.io/apimachinery/pkg/runtime/schema"
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

func TestNewObjectForResource(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	other := schema.GroupVersionKind{Group: "example.io", Version: "v1", Kind: "ConfigMap"}
	scheme.AddKnownTypeWithName(other, &corev1.ConfigMap{})

	for resource, want := range map[string]schema.GroupVersionKind{
		"v1.configmaps":            corev1.SchemeGroupVersion.WithKind("ConfigMap"),
		"example.io.v1.configmaps": other,
	} {
		obj, err := newObjectForResource(scheme, resource)
		if err != nil || obj == nil {
			t.Errorf("resolve %s: object %T, error %v", resource, obj, err)
			continue
		}
		if gvk := obj.GetObjectKind().GroupVersionKind(); gvk != want {
			t.Errorf("resolve %s: GVK %s, want %s", resource, gvk, want)
		}
	}
	if _, err := newObjectForResource(scheme, "configmaps"); err == nil {
		t.Error("expected ambiguous short resource name to fail")
	}
}
