// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
)

func TestScript(t *testing.T) {
	setup := func(t testing.TB, _ []string) *script.Engine {
		log := hivetest.Logger(t)
		c := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithIndex(&discoveryv1.EndpointSlice{}, derivedEndpointSliceByLocalNameIndex, derivedEndpointSliceByLocalNameIndexFunc).
			Build()
		cmds := k8stestutils.ControllerRuntimeScriptCommands(c, map[string]reconcile.Reconciler{
			"endpointslice": &mcsAPIEndpointSliceMirrorReconciler{Client: c, Logger: log, clusterName: "cluster1"},
		})
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		return &script.Engine{Cmds: cmds}
	}
	scripttest.Test(t, t.Context(), setup, nil, "testdata/scripts/*.txtar")
}
