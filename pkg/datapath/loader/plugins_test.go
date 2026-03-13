package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/bpf/testprogs"
	plugin "github.com/cilium/cilium/pkg/datapath/plugins/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/hivetest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestPluginDependencyGraph(t *testing.T) {
	type constraintSet struct {
		plugin string
		after  []string
		before []string
	}

	indexOf := func(s string, l []string) int {
		for i, e := range l {
			if e == s {
				return i
			}
		}

		return -1
	}

	intersect := func(a []string, b map[string]bool) []string {
		var result []string

		for _, s := range a {
			if !b[s] {
				continue
			}

			result = append(result, s)
		}

		return result
	}

	testCases := []struct {
		name        string
		constraints []constraintSet
		expectedErr error
	}{
		{
			name: "no constraints single",
			constraints: []constraintSet{
				{
					plugin: "a",
				},
			},
			expectedErr: nil,
		},
		{
			name: "no constraints multiple",
			constraints: []constraintSet{
				{
					plugin: "a",
				},
				{
					plugin: "b",
				},
				{
					plugin: "c",
				},
			},
			expectedErr: nil,
		},
		{
			name: "after constraint two nodes",
			constraints: []constraintSet{
				{
					plugin: "a",
					after:  []string{"b"},
				},
				{
					plugin: "b",
				},
			},
			expectedErr: nil,
		},
		{
			name: "before constraint two nodes",
			constraints: []constraintSet{
				{
					plugin: "a",
					before: []string{"b"},
				},
				{
					plugin: "b",
				},
			},
			expectedErr: nil,
		},
		{
			name: "multiple constraints multiple nodes",
			constraints: []constraintSet{
				{
					plugin: "a",
					before: []string{"b"},
				},
				{
					plugin: "b",
					after:  []string{"a"},
				},
				{
					plugin: "c",
					after:  []string{"a", "b"},
				},
				{
					plugin: "d",
					after:  []string{"c"},
				},
			},
			expectedErr: nil,
		},
		{
			name: "dependency cycle",
			constraints: []constraintSet{
				{
					plugin: "a",
					before: []string{"b"},
				},
				{
					plugin: "b",
					after:  []string{"a"},
				},
				{
					plugin: "c",
					after:  []string{"a", "b"},
					before: []string{"d"},
				},
				{
					plugin: "d",
					before: []string{"b"},
				},
			},
			expectedErr: &dependencyCycleError{
				cycle: []string{"b", "c", "d", "b"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &pluginDependencyGraph{}
			nodes := map[string]bool{}

			for _, c := range tc.constraints {
				nodes[c.plugin] = true
				g.addNode(c.plugin)
				for _, a := range c.after {
					g.after(c.plugin, a)
				}
				for _, b := range c.before {
					g.before(c.plugin, b)
				}
			}

			sorted, err := g.sort()
			if tc.expectedErr != nil {
				require.EqualError(t, err, tc.expectedErr.Error())
				return
			} else {
				require.NoError(t, err)
			}

			require.Lenf(t, sorted, len(nodes), "expected set of plugin names %v to equal the set of all nodes in the graph %v", sorted, nodes)
			require.Subsetf(t, sorted, nodes, "expected set of plugin names %v to equal the set of all nodes in the graph %v", sorted, nodes)
			for _, c := range tc.constraints {
				i := indexOf(c.plugin, sorted)
				require.Subsetf(t, sorted[i+1:], intersect(c.before, nodes), "expected all of %v to come before %s in sorted plugins %v", c.before, c.plugin, sorted)
				require.Subsetf(t, sorted[:i], intersect(c.after, nodes), "expected all of %v to come after %s in sorted plugins %v", c.after, c.plugin, sorted)
			}
		})
	}
}

type hookOutputValues struct {
	beforeProgramASeq     int32
	afterProgramARetParam int32
	afterProgramASeq      int32
	beforeProgramBSeq     int32
	afterProgramBRetParam int32
	afterProgramBSeq      int32
}

type baseOutputValues struct {
	aSeq int32
	bSeq int32
	retA int32
	retB int32
}

type outputValues struct {
	base baseOutputValues
	hook map[string]hookOutputValues
}

type hookInputValues struct {
	beforeProgramARet int32
	afterProgramARet  int32
	beforeProgramBRet int32
	afterProgramBRet  int32
}

type baseInputValues struct {
	aRet int32
	bRet int32
}

type inputValues struct {
	base baseInputValues
	hook map[string]hookInputValues
}

func runTestProgs(t *testing.T, inputValues inputValues, baseObjs testprogs.PluginsBaseObjects, pluginHooksObjs map[string]*ebpf.Collection) outputValues {
	t.Helper()

	outputs := outputValues{
		hook: map[string]hookOutputValues{},
	}

	require.NoError(t, baseObjs.A_ret.Set(inputValues.base.aRet))
	require.NoError(t, baseObjs.B_ret.Set(inputValues.base.bRet))

	for plugin, hookInputs := range inputValues.hook {
		objs := pluginHooksObjs[plugin]
		if objs == nil {
			continue
		}

		require.NoError(t, objs.Variables["before_program_a_ret"].Set(hookInputs.beforeProgramARet))
		require.NoError(t, objs.Variables["after_program_a_ret"].Set(hookInputs.afterProgramARet))
		require.NoError(t, objs.Variables["before_program_b_ret"].Set(hookInputs.beforeProgramBRet))
		require.NoError(t, objs.Variables["after_program_b_ret"].Set(hookInputs.afterProgramBRet))
	}

	retA, _, err := baseObjs.ProgramA.Test(make([]byte, 14))
	require.NoError(t, err)
	var zeroKey uint32 = 0
	var zeroValue int32 = 0
	require.NoError(t, baseObjs.Seq.Update(&zeroKey, &zeroValue, 0))
	retB, _, err := baseObjs.ProgramB.Test(make([]byte, 14))
	require.NoError(t, err)

	outputs.base.retA = int32(retA)
	outputs.base.retB = int32(retB)
	require.NoError(t, baseObjs.A_seq.Get(&outputs.base.aSeq))
	require.NoError(t, baseObjs.B_seq.Get(&outputs.base.bSeq))

	for plugin, objs := range pluginHooksObjs {
		if objs == nil {
			continue
		}

		var pluginHookOutputs hookOutputValues

		require.NoError(t, objs.Variables["before_program_a_seq"].Get(&pluginHookOutputs.beforeProgramASeq))
		require.NoError(t, objs.Variables["after_program_a_seq"].Get(&pluginHookOutputs.afterProgramASeq))
		require.NoError(t, objs.Variables["after_program_a_ret_param"].Get(&pluginHookOutputs.afterProgramARetParam))
		require.NoError(t, objs.Variables["before_program_b_seq"].Get(&pluginHookOutputs.beforeProgramBSeq))
		require.NoError(t, objs.Variables["after_program_b_seq"].Get(&pluginHookOutputs.afterProgramBSeq))
		require.NoError(t, objs.Variables["after_program_b_ret_param"].Get(&pluginHookOutputs.afterProgramBRetParam))

		outputs.hook[plugin] = pluginHookOutputs
	}

	return outputs
}

func maybeReportVerifierError(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve)
	}

	return err
}

func chooseHookProgram(hook *datapathplugins.InstrumentCollectionRequest_Hook) string {
	var name string

	if hook.Type == datapathplugins.HookType_PRE {
		name = "before_"
	} else {
		name = "after_"
	}

	return name + hook.Target
}

func TestPrivilegedHooksSpec(t *testing.T) {
	testutils.PrivilegedTest(t)

	preparePluginHooksSpec := func(baseColl *ebpf.Collection, hookColl *ebpf.CollectionSpec, hooks []*datapathplugins.InstrumentCollectionRequest_Hook) {
		usedHookPrograms := map[string]bool{}
		for _, hook := range hooks {
			hookProgramName := chooseHookProgram(hook)
			usedHookPrograms[hookProgramName] = true
			hookColl.Programs[hookProgramName].AttachTarget = baseColl.Programs[hook.Target]
			hookColl.Programs[hookProgramName].AttachTo = hook.AttachTarget.SubprogName
		}

		// prune any unused hook programs so they aren't loaded
		for name := range hookColl.Programs {
			if !usedHookPrograms[name] {
				delete(hookColl.Programs, name)
			}
		}
	}

	testCases := []struct {
		name                                 string
		hooks                                map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec
		inputValues                          inputValues
		expectedInstrumentCollectionRequests map[string]*datapathplugins.InstrumentCollectionRequest
		expectedOutputValues                 outputValues
	}{
		{
			name: "no hooks",
			hooks: map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{
				"plugin_a": {},
				"plugin_b": {},
			},
			inputValues: inputValues{
				hook: map[string]hookInputValues{
					"plugin_a": {},
					"plugin_b": {},
				},
			},
			expectedInstrumentCollectionRequests: map[string]*datapathplugins.InstrumentCollectionRequest{},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 1,
					bSeq: 1,
					retA: 0,
					retB: 0,
				},
				hook: map[string]hookOutputValues{},
			},
		},
		{
			name: "pre hooks basic",
			hooks: map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{
				"plugin_a": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
				},
				"plugin_b": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
					},
				},
			},
			inputValues: inputValues{
				hook: map[string]hookInputValues{
					"plugin_a": {
						beforeProgramARet: -1,
						beforeProgramBRet: -1,
					},
					"plugin_b": {
						beforeProgramARet: -1,
						beforeProgramBRet: -1,
					},
				},
			},
			expectedInstrumentCollectionRequests: map[string]*datapathplugins.InstrumentCollectionRequest{
				"plugin_a": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
					},
				},
				"plugin_b": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{

						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 3,
					bSeq: 3,
					retA: 0,
					retB: 0,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						beforeProgramASeq: 1,
						beforeProgramBSeq: 1,
					},
					"plugin_b": {
						beforeProgramASeq: 2,
						beforeProgramBSeq: 2,
					},
				},
			},
		},
		{
			name: "post hooks basic",
			hooks: map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{
				"plugin_a": {
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
				},
				"plugin_b": {
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
					},
				},
			},
			inputValues: inputValues{
				base: baseInputValues{
					aRet: 1,
					bRet: 1,
				},
				hook: map[string]hookInputValues{
					"plugin_a": {
						afterProgramARet: -1,
						afterProgramBRet: -1,
					},
					"plugin_b": {
						afterProgramARet: -1,
						afterProgramBRet: -1,
					},
				},
			},
			expectedInstrumentCollectionRequests: map[string]*datapathplugins.InstrumentCollectionRequest{
				"plugin_a": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
					},
				},
				"plugin_b": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 1,
					bSeq: 1,
					retA: 1,
					retB: 1,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						afterProgramASeq:      2,
						afterProgramARetParam: 1,
						afterProgramBSeq:      2,
						afterProgramBRetParam: 1,
					},
					"plugin_b": {
						afterProgramASeq:      3,
						afterProgramARetParam: 1,
						afterProgramBSeq:      3,
						afterProgramBRetParam: 1,
					},
				},
			},
		},
		{
			name: "pre and post hooks basic",
			hooks: map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{
				"plugin_a": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
				},
				"plugin_b": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
					},
				},
			},
			inputValues: inputValues{
				base: baseInputValues{
					aRet: 1,
					bRet: 1,
				},
				hook: map[string]hookInputValues{
					"plugin_a": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
					"plugin_b": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
				},
			},
			expectedInstrumentCollectionRequests: map[string]*datapathplugins.InstrumentCollectionRequest{
				"plugin_a": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},

						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
					},
				},
				"plugin_b": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 3,
					bSeq: 3,
					retA: 1,
					retB: 1,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						beforeProgramASeq:     1,
						afterProgramASeq:      4,
						afterProgramARetParam: 1,
						beforeProgramBSeq:     1,
						afterProgramBSeq:      4,
						afterProgramBRetParam: 1,
					},
					"plugin_b": {
						beforeProgramASeq:     2,
						afterProgramASeq:      5,
						afterProgramARetParam: 1,
						beforeProgramBSeq:     2,
						afterProgramBSeq:      5,
						afterProgramBRetParam: 1,
					},
				},
			},
		},
		{
			name: "pre hook override",
			hooks: map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{
				"plugin_a": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
				},
				"plugin_b": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
					},
				},
			},
			inputValues: inputValues{
				base: baseInputValues{
					aRet: 1,
					bRet: 1,
				},
				hook: map[string]hookInputValues{
					"plugin_a": {
						beforeProgramARet: 2,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
					"plugin_b": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: 2,
						afterProgramBRet:  -1,
					},
				},
			},
			expectedInstrumentCollectionRequests: map[string]*datapathplugins.InstrumentCollectionRequest{
				"plugin_a": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},

						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
					},
				},
				"plugin_b": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 0,
					bSeq: 0,
					retA: 2,
					retB: 2,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						beforeProgramASeq:     1,
						afterProgramASeq:      0,
						afterProgramARetParam: 0,
						beforeProgramBSeq:     1,
						afterProgramBSeq:      0,
						afterProgramBRetParam: 0,
					},
					"plugin_b": {
						beforeProgramASeq:     0,
						afterProgramASeq:      0,
						afterProgramARetParam: 0,
						beforeProgramBSeq:     2,
						afterProgramBSeq:      0,
						afterProgramBRetParam: 0,
					},
				},
			},
		},
		{
			name: "post hook override",
			hooks: map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{
				"plugin_a": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
						Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
							{
								Plugin: "plugin_b",
								Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
							},
						},
					},
				},
				"plugin_b": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
					},
					{
						Type:   datapathplugins.HookType_POST,
						Target: "program_b",
					},
				},
			},
			inputValues: inputValues{
				base: baseInputValues{
					aRet: 1,
					bRet: 1,
				},
				hook: map[string]hookInputValues{
					"plugin_a": {
						beforeProgramARet: -1,
						afterProgramARet:  2,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
					"plugin_b": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  2,
					},
				},
			},
			expectedInstrumentCollectionRequests: map[string]*datapathplugins.InstrumentCollectionRequest{
				"plugin_a": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},

						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_a"),
							},
						},
					},
				},
				"plugin_b": {
					Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_a",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_PRE,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Type:   datapathplugins.HookType_POST,
							Target: "program_b",
							AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
								SubprogName: postHookSubprogName("plugin_b"),
							},
						},
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 3,
					bSeq: 3,
					retA: 2,
					retB: 2,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						beforeProgramASeq:     1,
						afterProgramASeq:      4,
						afterProgramARetParam: 1,
						beforeProgramBSeq:     1,
						afterProgramBSeq:      4,
						afterProgramBRetParam: 1,
					},
					"plugin_b": {
						beforeProgramASeq:     2,
						afterProgramASeq:      0,
						afterProgramARetParam: 0,
						beforeProgramBSeq:     2,
						afterProgramBSeq:      5,
						afterProgramBRetParam: 1,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hooksSpec := newHooksSpec()
			for plugin, hooks := range tc.hooks {
				for _, hook := range hooks {
					hooksSpec.hook(hook.Target, hook.Type).addNode(plugin)
					for _, constraint := range hook.Constraints {
						switch constraint.Order {
						case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE:
							hooksSpec.hook(hook.Target, hook.Type).before(plugin, constraint.Plugin)
						case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_AFTER:
							hooksSpec.hook(hook.Target, hook.Type).after(plugin, constraint.Plugin)
						}
					}
				}
			}
			baseSpec, err := testprogs.LoadPluginsBase()
			require.NoError(t, err)
			loadHooksRequests, err := hooksSpec.instrumentCollection(baseSpec)
			require.NoError(t, err)
			if diff := cmp.Diff(
				tc.expectedInstrumentCollectionRequests,
				loadHooksRequests,
				protocmp.SortRepeated(func(a, b *datapathplugins.InstrumentCollectionRequest_Hook) bool {
					if a.Target == b.Target {
						return a.Type < b.Type
					}

					return a.Target < b.Target
				}),
				protocmp.Transform(),
			); diff != "" {
				t.Fatalf("loadHooksRequests did not match what was expected (-want +got):\n%s", diff)
			}
			baseColl, err := ebpf.NewCollection(baseSpec)
			require.NoError(t, maybeReportVerifierError(err))
			defer baseColl.Close()

			pluginHooksObjs := map[string]*ebpf.Collection{}

			for plugin, req := range loadHooksRequests {
				pluginHooksSpec, err := testprogs.LoadPluginsHooks()
				require.NoError(t, err)
				preparePluginHooksSpec(baseColl, pluginHooksSpec, req.Hooks)
				pluginHooks, err := ebpf.NewCollectionWithOptions(pluginHooksSpec, ebpf.CollectionOptions{
					MapReplacements: map[string]*ebpf.Map{
						"seq": baseColl.Maps["seq"],
					},
				})
				require.NoError(t, maybeReportVerifierError(err))
				defer pluginHooks.Close()

				for _, hook := range req.Hooks {
					link, err := link.AttachFreplace(
						baseColl.Programs[hook.Target],
						hook.AttachTarget.SubprogName,
						pluginHooks.Programs[chooseHookProgram(hook)],
					)
					require.NoError(t, err)
					defer link.Close()
				}

				pluginHooksObjs[plugin] = pluginHooks
			}

			var baseObjs testprogs.PluginsBaseObjects
			require.NoError(t, baseColl.Assign(&baseObjs))
			outputs := runTestProgs(t, tc.inputValues, baseObjs, pluginHooksObjs)
			if diff := cmp.Diff(
				tc.expectedOutputValues,
				outputs,
				cmp.AllowUnexported(outputValues{}, baseOutputValues{}, hookOutputValues{}),
			); diff != "" {
				t.Fatalf("outputs did not match what was expected (-want +got):\n%s", diff)
			}
		})
	}
}

type fakePluginRegistry map[string]*fakePlugin

func (r fakePluginRegistry) IsEnabled() bool {
	return true
}

func (r fakePluginRegistry) Register(dpp *api_v2alpha1.CiliumDatapathPlugin) error {
	return nil
}

func (r fakePluginRegistry) Unregister(dpp *api_v2alpha1.CiliumDatapathPlugin) error {
	return nil
}

func (r fakePluginRegistry) Plugins() plugin.Plugins {
	result := plugin.Plugins{}

	for _, p := range r {
		result[p.name] = p
	}

	return result
}

func (r fakePluginRegistry) closeAll() {
	for _, p := range r {
		if p.coll != nil {
			p.coll.Close()
		}
	}
}

type transaction struct {
	prepareHooksReq  *datapathplugins.PrepareCollectionRequest
	prepareHooksResp *datapathplugins.PrepareCollectionResponse
	prepareHooksErr  error
	loadHooksReq     *datapathplugins.InstrumentCollectionRequest
	loadHooksResp    *datapathplugins.InstrumentCollectionResponse
	loadHooksErr     error
}

var _ plugin.Plugin = &fakePlugin{}

type fakePlugin struct {
	name             string
	attachmentPolicy api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
	transaction      *transaction

	coll *ebpf.Collection
}

func (p *fakePlugin) Name() string {
	return p.name
}

func (p *fakePlugin) AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy {
	return p.attachmentPolicy
}

func (p *fakePlugin) DeepEqual(o plugin.Plugin) bool {
	return false
}

func (p *fakePlugin) PrepareCollection(ctx context.Context, in *datapathplugins.PrepareCollectionRequest, opts ...grpc.CallOption) (*datapathplugins.PrepareCollectionResponse, error) {
	p.transaction.prepareHooksReq = in

	if p.transaction.prepareHooksErr != nil {
		return nil, p.transaction.prepareHooksErr
	}

	return p.transaction.prepareHooksResp, nil
}

func (p *fakePlugin) InstrumentCollection(ctx context.Context, in *datapathplugins.InstrumentCollectionRequest, opts ...grpc.CallOption) (*datapathplugins.InstrumentCollectionResponse, error) {
	p.transaction.loadHooksReq = in

	if p.transaction.loadHooksErr != nil {
		return nil, p.transaction.loadHooksErr
	}

	spec, err := testprogs.LoadPluginsHooks()
	if err != nil {
		return nil, fmt.Errorf("loading plugin hooks spec: %w", err)
	}

	targetProgs := map[ebpf.ProgramID]*ebpf.Program{}
	usedHookPrograms := map[string]bool{}

	for _, h := range in.Hooks {
		progName := chooseHookProgram(h)
		progSpec := spec.Programs[progName]
		if progSpec == nil {
			return nil, fmt.Errorf("unknown program: %s", progName)
		}

		usedHookPrograms[progName] = true
		id := ebpf.ProgramID(h.AttachTarget.ProgramId)
		if targetProgs[id] == nil {
			targetProg, err := ebpf.NewProgramFromID(id)
			if err != nil {
				return nil, fmt.Errorf("loading target program %d: %w", h.AttachTarget.ProgramId, err)
			}
			defer targetProg.Close()
			targetProgs[id] = targetProg
		}

		progSpec.AttachTarget = targetProgs[id]
		progSpec.AttachTo = h.AttachTarget.SubprogName
	}

	// prune any unused hook programs so they aren't loaded
	for name := range spec.Programs {
		if !usedHookPrograms[name] {
			delete(spec.Programs, name)
		}
	}

	seqID := in.Collection.Maps["seq"].Id
	seq, err := ebpf.NewMapFromID(ebpf.MapID(seqID))
	if err != nil {
		return nil, fmt.Errorf("loading seq map: %w", err)
	}
	defer seq.Close()

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"seq": seq,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("loading plugin hooks: %w", err)
	}

	for _, h := range in.Hooks {
		progName := chooseHookProgram(h)
		prog := coll.Programs[progName]

		if err := prog.Pin(h.PinPath); err != nil {
			coll.Close()
			return nil, fmt.Errorf("pinning program %s to %s: %w", progName, h.PinPath, err)
		}
	}

	p.coll = coll

	return p.transaction.loadHooksResp, nil
}

func TestPrivilegedLoadAndAssignWithPlugins(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		name                 string
		inputValues          inputValues
		attachmentPolicies   map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
		transactions         map[string]transaction
		expectedOutputValues outputValues
		expectedErr          error
	}{
		{
			name: "pre and post hooks basic",
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksResp: &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
							},
						},
						Cookie: "plugin_b_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_b"),
								},
							},
						},
						Cookie: "plugin_b_cookie",
					},
					loadHooksResp: &datapathplugins.InstrumentCollectionResponse{},
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				base: baseInputValues{
					aRet: 1,
					bRet: 1,
				},
				hook: map[string]hookInputValues{
					"plugin_a": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
					"plugin_b": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 3,
					bSeq: 3,
					retA: 1,
					retB: 1,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						beforeProgramASeq:     1,
						afterProgramASeq:      4,
						afterProgramARetParam: 1,
						beforeProgramBSeq:     1,
						afterProgramBSeq:      4,
						afterProgramBRetParam: 1,
					},
					"plugin_b": {
						beforeProgramASeq:     2,
						afterProgramASeq:      5,
						afterProgramARetParam: 1,
						beforeProgramBSeq:     2,
						afterProgramBSeq:      5,
						afterProgramBRetParam: 1,
					},
				},
			},
		},
		{
			name: "plugin_b returns an error in PrepareCollection() with AttachmentPolicyAlways",
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksResp: &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksErr: errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			expectedErr: errors.New("some error"),
		},
		{
			name: "plugin_b returns an error in PrepareCollection() with AttachmentPolicyBestEffort",
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksResp: &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksErr: errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyBestEffort,
			},
			inputValues: inputValues{
				base: baseInputValues{
					aRet: 1,
					bRet: 1,
				},
				hook: map[string]hookInputValues{
					"plugin_a": {
						beforeProgramARet: -1,
						afterProgramARet:  -1,
						beforeProgramBRet: -1,
						afterProgramBRet:  -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: baseOutputValues{
					aSeq: 2,
					bSeq: 2,
					retA: 1,
					retB: 1,
				},
				hook: map[string]hookOutputValues{
					"plugin_a": {
						beforeProgramASeq:     1,
						afterProgramASeq:      3,
						afterProgramARetParam: 1,
						beforeProgramBSeq:     1,
						afterProgramBSeq:      3,
						afterProgramBRetParam: 1,
					},
				},
			},
		},
		{
			name: "plugin_b returns an error in InstrumentCollection() with AttachmentPolicyAlways",
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksResp: &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
							},
						},
						Cookie: "plugin_b_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_b"),
								},
							},
						},
						Cookie: "plugin_b_cookie",
					},
					loadHooksErr: errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			expectedErr: errors.New("some error"),
		},
		{
			name: "plugin_b returns an error in InstrumentCollection() with AttachmentPolicyBestEffort",
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								Constraints: []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
									{
										Plugin: "plugin_b",
										Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
									},
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_a"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_a"),
								},
							},
						},
						Cookie: "plugin_a_cookie",
					},
					loadHooksResp: &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: &datapathplugins.PrepareCollectionRequest{
						Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
							Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
					},
					prepareHooksResp: &datapathplugins.PrepareCollectionResponse{
						Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
							},
						},
						Cookie: "plugin_b_cookie",
					},
					loadHooksReq: &datapathplugins.InstrumentCollectionRequest{
						Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
							Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{
								"program_a": {},
								"program_b": {},
							},
							Maps: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{
								"seq":  {},
								".bss": {},
							},
						},
						LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
						AttachmentContext: &datapathplugins.AttachmentContext{},
						Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_a",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_PRE,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: preHookSubprogName("plugin_b"),
								},
							},
							{
								Type:   datapathplugins.HookType_POST,
								Target: "program_b",
								AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
									SubprogName: postHookSubprogName("plugin_b"),
								},
							},
						},
						Cookie: "plugin_b_cookie",
					},
					loadHooksErr: errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyBestEffort,
			},
			expectedErr: errors.New("some error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			tmp := testutils.TempBPFFS(t)
			plugins := fakePluginRegistry{}
			defer plugins.closeAll()

			for p, t := range tc.transactions {
				plugins[p] = &fakePlugin{
					name:             p,
					attachmentPolicy: tc.attachmentPolicies[p],
					transaction: &transaction{
						prepareHooksResp: t.prepareHooksResp,
						prepareHooksErr:  t.prepareHooksErr,
						loadHooksResp:    t.loadHooksResp,
						loadHooksErr:     t.loadHooksErr,
					},
				}
			}

			l := bpfCollectionLoader{
				pluginOperationsDir: bpffsPluginsOperationsDir(tmp),
				pluginsEnabled:      true,
			}

			baseSpec, err := testprogs.LoadPluginsBase()
			require.NoError(t, err)

			var baseObjs testprogs.PluginsBaseObjects
			pinsDir := filepath.Join(tmp, "pins_dir")
			commit, cleanup, err := l.LoadAndAssign(
				t.Context(),
				logger,
				&baseObjs,
				baseSpec,
				&bpf.CollectionOptions{},
				&datapath.LocalNodeConfiguration{
					Plugins: plugins.Plugins(),
				},
				&datapathplugins.AttachmentContext{},
				pinsDir,
			)
			if tc.expectedErr != nil {
				require.ErrorContains(t, err, tc.expectedErr.Error())
				return
			} else {
				require.NoError(t, err)
			}

			require.NoError(t, commit())
			cleanup()

			for name, plugin := range plugins {
				if diff := cmp.Diff(
					tc.transactions[name],
					*plugin.transaction,
					cmp.AllowUnexported(transaction{}),
					cmpopts.EquateErrors(),
					protocmp.Transform(),
					protocmp.SortRepeated(func(a, b *datapathplugins.InstrumentCollectionRequest_Hook) bool {
						if a.Target == b.Target {
							return a.Type < b.Type
						}

						return a.Target < b.Target
					}),
					protocmp.IgnoreFields(&datapathplugins.InstrumentCollectionRequest{}, "pins"),
					protocmp.IgnoreFields(&datapathplugins.InstrumentCollectionRequest_Collection_Map{}, "id"),
					protocmp.IgnoreFields(&datapathplugins.InstrumentCollectionRequest_Collection_Program{}, "id"),
					protocmp.IgnoreFields(&datapathplugins.InstrumentCollectionRequest_Hook{}, "pin_path"),
					protocmp.IgnoreFields(&datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{}, "program_id"),
				); diff != "" {
					t.Fatalf("transaction for plugin %s did not match what was expected (-want +got):\n%s", name, diff)
				}
			}

			pluginHooksObjs := map[string]*ebpf.Collection{}
			for name, plugin := range plugins {
				pluginHooksObjs[name] = plugin.coll
			}

			outputs := runTestProgs(t, tc.inputValues, baseObjs, pluginHooksObjs)
			if diff := cmp.Diff(
				tc.expectedOutputValues,
				outputs,
				cmp.AllowUnexported(outputValues{}, baseOutputValues{}, hookOutputValues{}),
			); diff != "" {
				t.Errorf("outputs did not match what was expected (-want +got):\n%s", diff)
			}
		})
	}
}

// TODO: links should be cleaned up when switching modes
