// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

type configTestCase struct {
	name              string
	configs           map[resource.Key]*config
	currentNodeLabels map[string]string
	kind              resource.EventKind
	configSpecOpt     func(spec *ciliumv2.CiliumEnvoyConfigSpec)
	shouldFailFor     []string
	configKey         resource.Key
	expectedError     bool
	expectedAdded     []string
	expectedUpdated   []string
	expectedDeleted   []string
}

var configTestCases = []configTestCase{
	// Additions
	{
		name:              "Upsert event: new / no nodeselector / empty list of node labels / match",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{"test/test"},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name:              "Upsert event: new / no nodeselector / populated list of node labels / match",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{"test/test"},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name:              "Upsert event: new / existing nodeselector / populated list of node labels / match",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "infra"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{"test/test"},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name:              "Upsert event: new / existing nodeselector / populated list of node labels / no match",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "app"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name:              "Upsert event: new / existing nodeselector / empty list of node labels / no match",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "app"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},

	// Updates
	{
		name: "Upsert event: update / no nodeselector / empty list of node labels / match / previously match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", nil, true),
		},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{"test/test"},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: update / no nodeselector / empty list of node labels / match / previously no match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", nil, false),
		},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{"test/test"},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: new / no nodeselector / populated list of node labels / match / previously match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", nil, true),
		},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{"test/test"},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: new / no nodeselector / populated list of node labels / match / previously no match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", nil, false),
		},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{"test/test"},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: new / existing nodeselector / populated list of node labels / match / previously match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", map[string]string{"role": "infra"}, true),
		},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "infra"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{"test/test"},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: new / existing nodeselector / populated list of node labels / match / previously no match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", map[string]string{"role": "infra"}, false),
		},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "infra"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{"test/test"},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: new / existing nodeselector / populated list of node labels / no match / previously match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", map[string]string{"role": "infra"}, true),
		},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "app"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{"test/test"},
	},
	{
		name: "Upsert event: new / existing nodeselector / populated list of node labels / no match / previously no match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", map[string]string{"role": "app"}, false),
		},
		currentNodeLabels: map[string]string{"role": "infra", "name": "node1"},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "app"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name: "Upsert event: new / existing nodeselector / empty list of node labels / no match / previously match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", map[string]string{"role": "infra"}, true),
		},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "app"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{"test/test"},
	},
	{
		name: "Upsert event: new / existing nodeselector / empty list of node labels / no match / previously no match",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", map[string]string{"role": "app"}, false),
		},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withNodeLabelSelector(map[string]string{"role": "app"}),
		kind:              resource.Upsert,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},

	// Deletions
	{
		name: "Delete event: existing / previously matched",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", nil, true),
		},
		currentNodeLabels: map[string]string{},
		configKey:         resource.Key{Namespace: "test", Name: "test"},
		kind:              resource.Delete,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{"test/test"},
	},
	{
		name: "Delete event: existing / previously not matched",
		configs: map[resource.Key]*config{
			{Namespace: "test", Name: "test"}: testConfig("test", "test", nil, false),
		},
		currentNodeLabels: map[string]string{},
		configKey:         resource.Key{Namespace: "test", Name: "test"},
		kind:              resource.Delete,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
	{
		name:              "Delete event: not existing",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{},
		configKey:         resource.Key{Namespace: "test", Name: "test"},
		kind:              resource.Delete,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},

	// Synced
	{
		name:              "Sync events shouldn't be handled",
		configs:           map[resource.Key]*config{},
		currentNodeLabels: map[string]string{},
		configSpecOpt:     withoutNodeSelector(),
		kind:              resource.Sync,
		expectedError:     false,
		expectedAdded:     []string{},
		expectedUpdated:   []string{},
		expectedDeleted:   []string{},
	},
}

func TestHandleCECEvent(t *testing.T) {
	executeForConfigType(t,
		configTestCases,
		testCEC,
		func(reconciler *ciliumEnvoyConfigReconciler) func(context.Context, resource.Event[*ciliumv2.CiliumEnvoyConfig]) error {
			return reconciler.handleCECEvent
		},
	)
}

func TestHandleCCECEvent(t *testing.T) {
	executeForConfigType(t,
		configTestCases,
		testCCEC,
		func(reconciler *ciliumEnvoyConfigReconciler) func(context.Context, resource.Event[*ciliumv2.CiliumClusterwideEnvoyConfig]) error {
			return reconciler.handleCCECEvent
		},
	)
}

// executeForConfigType executes the given test casese for the CEC and CCEC
func executeForConfigType[T k8sRuntime.Object](t *testing.T,
	tests []configTestCase,
	createConfigFunc func(opts ...cecOpts) T,
	handleEventFunc func(*ciliumEnvoyConfigReconciler) func(context.Context, resource.Event[T]) error,
) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)

			manager := &fakeCECManager{
				shouldFailFor: tc.shouldFailFor,
			}

			reconciler := newCiliumEnvoyConfigReconciler(logger, manager)

			// init current state
			configs := map[resource.Key]*config{}
			maps.Copy(configs, tc.configs)
			reconciler.configs = configs

			currentNodeLabels := map[string]string{}
			maps.Copy(currentNodeLabels, tc.currentNodeLabels)
			reconciler.localNodeLabels = currentNodeLabels

			doneCalled := false
			var doneError error

			doneFunc := func(err error) {
				doneCalled = true
				doneError = err
			}

			event := resource.Event[T]{}
			event.Kind = tc.kind
			if len(tc.configKey.Name) == 0 && len(tc.configKey.Namespace) == 0 && tc.configSpecOpt != nil {
				event.Object = createConfigFunc(tc.configSpecOpt)
				event.Key = resource.NewKey(event.Object)
			} else {
				event.Key = tc.configKey
			}
			event.Done = doneFunc

			err := handleEventFunc(reconciler)(context.Background(), event)
			assert.Equal(t, tc.expectedError, err != nil)

			assert.True(t, doneCalled, "Done must be called on the event in all cases")
			assert.Equal(t, tc.expectedError, doneError != nil, "Expected done error should match")

			assert.ElementsMatch(t, tc.expectedAdded, manager.addedConfigNames, "Expected added configs should match")
			assert.ElementsMatch(t, tc.expectedUpdated, manager.updatedConfigNames, "Expected updated configs should match")
			assert.ElementsMatch(t, tc.expectedDeleted, manager.deletedConfigNames, "Expected deleted configs should match")

			// Assert that the stored state whether a config selects the local Node or not has been updated
			for _, n := range append(manager.addedConfigNames, manager.updatedConfigNames...) {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.True(t, reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode)
			}
			for _, n := range manager.deletedConfigNames {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				if event.Kind == resource.Delete {
					assert.NotContains(t, reconciler.configs, resource.Key{Namespace: ns, Name: name},
						"Deleted configs due to deletion event should be deleted from local cache")
				} else {
					assert.False(t, reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode,
						"Deleted configs due to update should be kept in the local cache - but marked as not selecting local node")
				}
			}
		})
	}
}

type cecOpts func(spec *ciliumv2.CiliumEnvoyConfigSpec)

func withoutNodeSelector() func(spec *ciliumv2.CiliumEnvoyConfigSpec) {
	return func(spec *ciliumv2.CiliumEnvoyConfigSpec) {
		spec.NodeSelector = nil
	}
}

func withNodeLabelSelector(labels map[string]string) func(spec *ciliumv2.CiliumEnvoyConfigSpec) {
	return func(spec *ciliumv2.CiliumEnvoyConfigSpec) {
		spec.NodeSelector = &slim_metav1.LabelSelector{
			MatchLabels: labels,
		}
	}
}

func testCEC(opts ...cecOpts) *ciliumv2.CiliumEnvoyConfig {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "test",
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{},
	}

	for _, opt := range opts {
		opt(&cec.Spec)
	}

	return cec
}

func testCCEC(opts ...cecOpts) *ciliumv2.CiliumClusterwideEnvoyConfig {
	ccec := &ciliumv2.CiliumClusterwideEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "test",
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{},
	}

	for _, opt := range opts {
		opt(&ccec.Spec)
	}

	return ccec
}

func TestReconcileExistingConfigs(t *testing.T) {
	tests := []struct {
		name                  string
		configs               map[resource.Key]*config
		currentNodeLabels     map[string]string
		failFor               []string
		expectedError         bool
		expectedErrorMessages []string
		expectedAdded         []string
		expectedDeleted       []string
	}{
		{
			name:              "No changes if no configs are present",
			configs:           map[resource.Key]*config{},
			currentNodeLabels: map[string]string{},
			expectedError:     false,
			expectedAdded:     []string{},
			expectedDeleted:   []string{},
		},
		{
			name: "No changes if there are no changes in configs selecting nodes or not",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", nil, true),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", nil, true),
			},
			currentNodeLabels: map[string]string{
				"role": "worker",
			},
			expectedError:   false,
			expectedAdded:   []string{},
			expectedDeleted: []string{},
		},
		{
			name: "Delete configs that no longer select the local node",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", map[string]string{"role": "infra"}, true),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", nil, true),
			},
			currentNodeLabels: map[string]string{
				"role": "worker",
			},
			expectedError:   false,
			expectedAdded:   []string{},
			expectedDeleted: []string{"ns1/config1"},
		},
		{
			name: "Add configs that start to select the local node",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", map[string]string{"role": "infra"}, false),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", nil, true),
			},
			currentNodeLabels: map[string]string{
				"role": "infra",
			},
			expectedError:   false,
			expectedAdded:   []string{"ns1/config1"},
			expectedDeleted: []string{},
		},
		{
			name: "Multiple changes",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", map[string]string{"role": "infra", "node": "node1"}, false),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", map[string]string{"role": "infra", "node": "node1"}, false),
				{Namespace: "ns1", Name: "config3"}: testConfig("ns1", "config3", map[string]string{"role": "infra", "node": "node1", "environment": "test"}, false),
				{Namespace: "ns1", Name: "config4"}: testConfig("ns1", "config4", nil, true),
				{Namespace: "ns1", Name: "config5"}: testConfig("ns1", "config5", map[string]string{"role": "worker", "node": "node1"}, true),
				{Namespace: "ns1", Name: "config6"}: testConfig("ns1", "config6", map[string]string{"role": "worker", "node": "node1"}, true),
				{Namespace: "ns1", Name: "config7"}: testConfig("ns1", "config7", map[string]string{"role": "worker", "node": "node1", "environment": "test"}, false),
			},
			currentNodeLabels: map[string]string{
				"node": "node1",
				"role": "infra",
			},
			expectedError:   false,
			expectedAdded:   []string{"ns1/config1", "ns1/config2"},
			expectedDeleted: []string{"ns1/config5", "ns1/config6"},
		},
		{
			name: "Failures during updating individual configs should't abort",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", map[string]string{"role": "infra", "node": "node1"}, false),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", map[string]string{"role": "infra", "node": "node1"}, false),
				{Namespace: "ns1", Name: "config3"}: testConfig("ns1", "config3", map[string]string{"role": "infra", "node": "node1", "environment": "test"}, false),
				{Namespace: "ns1", Name: "config4"}: testConfig("ns1", "config4", nil, true),
				{Namespace: "ns1", Name: "config5"}: testConfig("ns1", "config5", map[string]string{"role": "worker", "node": "node1"}, true),
				{Namespace: "ns1", Name: "config6"}: testConfig("ns1", "config6", map[string]string{"role": "worker", "node": "node1"}, true),
				{Namespace: "ns1", Name: "config7"}: testConfig("ns1", "config7", map[string]string{"role": "worker", "node": "node1", "environment": "test"}, false),
			},
			currentNodeLabels: map[string]string{
				"node": "node1",
				"role": "infra",
			},
			failFor:       []string{"ns1/config2", "ns1/config5"},
			expectedError: true,
			expectedErrorMessages: []string{
				"failed to reconcile existing config (ns1/config2): failed to add config ns1/config2",
				"failed to reconcile existing config (ns1/config5): failed to delete config ns1/config5",
			},
			expectedAdded:   []string{"ns1/config1"},
			expectedDeleted: []string{"ns1/config6"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)

			manager := &fakeCECManager{
				shouldFailFor: tc.failFor,
			}

			reconciler := newCiliumEnvoyConfigReconciler(logger, manager)

			// init current state
			reconciler.configs = make(map[resource.Key]*config, len(tc.configs))
			for k, v := range tc.configs {
				reconciler.configs[k] = &config{
					meta:             v.meta,
					spec:             v.spec.DeepCopy(),
					selectsLocalNode: v.selectsLocalNode,
				}
			}
			reconciler.localNodeLabels = tc.currentNodeLabels

			err := reconciler.reconcileExistingConfigs(context.Background())
			assert.Equal(t, tc.expectedError, err != nil)
			if tc.expectedError {
				for _, expectedErrorMessage := range tc.expectedErrorMessages {
					assert.ErrorContains(t, err, expectedErrorMessage)
				}
			}

			assert.ElementsMatch(t, tc.expectedAdded, manager.addedConfigNames)
			assert.ElementsMatch(t, tc.expectedDeleted, manager.deletedConfigNames)

			assert.Empty(t, manager.updatedConfigNames, "Should never update an existing config")

			// Assert that the stored state whether a config selects the local Node or not has been updated
			for _, n := range manager.addedConfigNames {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.True(t, reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode)
			}

			for _, n := range manager.deletedConfigNames {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.False(t, reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode)
			}

			// Check that state didn't change for configs that failed to reconcile
			for _, n := range tc.failFor {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.Equal(t,
					tc.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode,
					reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode,
					"Configs shouldn't change their selection state if their reconciliation failed",
				)
			}
		})
	}
}

func TestHandleLocalNodeLabels(t *testing.T) {
	tests := []struct {
		name              string
		configs           map[resource.Key]*config
		currentNodeLabels map[string]string
		newNodeLabels     map[string]string
		failFor           []string
		expectedDeleted   []string
	}{
		{
			name:              "No changes if no configs are present",
			configs:           map[resource.Key]*config{},
			currentNodeLabels: map[string]string{},
			newNodeLabels:     map[string]string{},
			expectedDeleted:   []string{},
		},
		{
			name: "No changes if node labels don't change",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", nil, true),
			},
			currentNodeLabels: map[string]string{
				"role": "infra",
			},
			newNodeLabels: map[string]string{
				"role": "infra",
			},
			expectedDeleted: []string{},
		},
		{
			name: "No changes if there are no changes in configs selecting nodes or not",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", nil, true),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", nil, true),
			},
			currentNodeLabels: map[string]string{
				"role": "infra",
			},
			newNodeLabels: map[string]string{
				"role": "worker",
			},
			expectedDeleted: []string{},
		},
		{
			name: "Updated node labels triggers a best-effort reconciliation of existing configs",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config1"}: testConfig("ns1", "config1", map[string]string{"role": "infra"}, true),
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", nil, true),
			},
			currentNodeLabels: map[string]string{
				"role": "infra",
			},
			newNodeLabels: map[string]string{
				"role": "worker",
			},
			expectedDeleted: []string{"ns1/config1"},
		},
		{
			name: "Failures during updating individual configs should't result in any error - as it's only best effort",
			configs: map[resource.Key]*config{
				{Namespace: "ns1", Name: "config2"}: testConfig("ns1", "config2", map[string]string{"role": "infra", "node": "node1"}, false),
			},
			currentNodeLabels: map[string]string{
				"node": "node1",
				"role": "worker",
			},
			newNodeLabels: map[string]string{
				"node": "node1",
				"role": "infra",
			},
			failFor:         []string{"ns1/config2"},
			expectedDeleted: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)

			manager := &fakeCECManager{
				shouldFailFor: tc.failFor,
			}

			reconciler := newCiliumEnvoyConfigReconciler(logger, manager)

			// init current state
			reconciler.configs = make(map[resource.Key]*config, len(tc.configs))
			for k, v := range tc.configs {
				reconciler.configs[k] = &config{
					meta:             v.meta,
					spec:             v.spec.DeepCopy(),
					selectsLocalNode: v.selectsLocalNode,
				}
			}
			reconciler.localNodeLabels = tc.currentNodeLabels

			node := node.LocalNode{Node: types.Node{Name: "test", Labels: tc.newNodeLabels}}

			err := reconciler.handleLocalNodeEvent(context.Background(), node)
			assert.NoError(t, err)

			assert.Equal(t, tc.newNodeLabels, reconciler.localNodeLabels)

			assert.ElementsMatch(t, tc.expectedDeleted, manager.deletedConfigNames)

			assert.Empty(t, manager.addedConfigNames)
			assert.Empty(t, manager.updatedConfigNames, "Should never update an existing config")

			// Assert that the stored state whether a config selects the local Node or not has been updated
			for _, n := range manager.addedConfigNames {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.True(t, reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode)
			}

			for _, n := range manager.deletedConfigNames {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.False(t, reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode)
			}

			// Check that state didn't change for configs that failed to reconcile
			for _, n := range tc.failFor {
				split := strings.Split(n, "/")
				ns, name := split[0], split[1]
				assert.Equal(t,
					tc.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode,
					reconciler.configs[resource.Key{Namespace: ns, Name: name}].selectsLocalNode,
					"Configs shouldn't change their selection state if their reconciliation failed",
				)
			}
		})
	}
}

func testConfig(namespace string, name string, nodeSelectorLabels map[string]string, selectsLocalNode bool) *config {
	cfg := &config{
		meta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		spec:             &ciliumv2.CiliumEnvoyConfigSpec{},
		selectsLocalNode: selectsLocalNode,
	}

	if nodeSelectorLabels != nil {
		cfg.spec.NodeSelector = &slim_metav1.LabelSelector{
			MatchLabels: nodeSelectorLabels,
		}
	}

	return cfg
}

type fakeCECManager struct {
	addedConfigNames   []string
	deletedConfigNames []string
	updatedConfigNames []string
	shouldFailFor      []string
}

var _ ciliumEnvoyConfigManager = &fakeCECManager{}

func (r *fakeCECManager) addCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error {
	namespacedName := fmt.Sprintf("%s/%s", cecObjectMeta.Namespace, cecObjectMeta.Name)

	if slices.Contains(r.shouldFailFor, namespacedName) {
		return fmt.Errorf("failed to add config %s", namespacedName)
	}

	r.addedConfigNames = append(r.addedConfigNames, namespacedName)

	return nil
}

func (r *fakeCECManager) deleteCiliumEnvoyConfig(cecObjectMeta metav1.ObjectMeta, cecSpec *ciliumv2.CiliumEnvoyConfigSpec) error {
	namespacedName := fmt.Sprintf("%s/%s", cecObjectMeta.Namespace, cecObjectMeta.Name)

	if slices.Contains(r.shouldFailFor, namespacedName) {
		return fmt.Errorf("failed to delete config %s", namespacedName)
	}

	r.deletedConfigNames = append(r.deletedConfigNames, namespacedName)

	return nil
}

func (r *fakeCECManager) updateCiliumEnvoyConfig(oldCECObjectMeta metav1.ObjectMeta, oldCECSpec *ciliumv2.CiliumEnvoyConfigSpec, newCECObjectMeta metav1.ObjectMeta, newCECSpec *ciliumv2.CiliumEnvoyConfigSpec) error {
	namespacedName := fmt.Sprintf("%s/%s", newCECObjectMeta.Namespace, newCECObjectMeta.Name)

	if slices.Contains(r.shouldFailFor, namespacedName) {
		return fmt.Errorf("failed to update config %s", namespacedName)
	}

	r.updatedConfigNames = append(r.updatedConfigNames, namespacedName)

	return nil
}
