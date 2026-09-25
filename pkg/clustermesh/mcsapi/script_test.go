// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
)

func TestScript(t *testing.T) {
	derivedService := derivedName(types.NamespacedName{Name: "full", Namespace: "default"})
	atLimit := strings.Repeat("a", 253-len(derivedService)-1)
	overLimit := strings.Repeat("a", 254-len(derivedService)-1)
	prefixedAtLimit := "full-" + strings.Repeat("b", 253-len(derivedService)-1)
	prefixedOverLimit := "full-" + strings.Repeat("b", 254-len(derivedService)-1)
	env := []string{
		"AT_LIMIT=" + atLimit,
		"OVER_LIMIT=" + overLimit,
		"PREFIXED_AT_LIMIT=" + prefixedAtLimit,
		"PREFIXED_OVER_LIMIT=" + prefixedOverLimit,
		"DERIVED_AT_LIMIT=" + derivedService + "-" + atLimit,
		"DERIVED_OVER_LIMIT=" + derivedService + "-" + strings.Repeat("a", 223) + "-2bkdbdh4ft",
		"DERIVED_PREFIXED_AT_LIMIT=" + derivedService + "-" + strings.TrimPrefix(prefixedAtLimit, "full-"),
		"DERIVED_PREFIXED_OVER_LIMIT=" + derivedService + "-" + strings.Repeat("b", 223) + "-5gt6bkmtcd",
	}

	setup := func(t testing.TB, args []string) *script.Engine {
		log := hivetest.Logger(t)
		scheme := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		utilruntime.Must(mcsapiv1beta1.AddToScheme(scheme))
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithIndex(&discoveryv1.EndpointSlice{}, derivedEndpointSliceByLocalNameIndex, derivedEndpointSliceByLocalNameIndexFunc).
			Build()
		cmds := k8stestutils.ControllerRuntimeScriptCommands(
			c,
			map[string]reconcile.Reconciler{"endpointslice-mirror": &mcsAPIEndpointSliceMirrorReconciler{
				Client: c, Logger: log, clusterName: "cluster1",
			}},
		)
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    100 * time.Millisecond,
			MaxRetryInterval: time.Second,
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	scripttest.Test(t, ctx, setup, env, "testdata/*.txtar")
}
