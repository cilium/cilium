// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/bpf/testprogs"
	"github.com/cilium/cilium/pkg/datapath/config"
	plugin "github.com/cilium/cilium/pkg/datapath/plugins/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/testutils"

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

type outputValues struct {
	base    map[string]int32
	returns map[string]uint32
	hook    map[string]map[string]int32
}

type inputValues struct {
	base map[string]int32
	hook map[string]map[string]int32
}

func supportsTestRun(progType ebpf.ProgramType) bool {
	switch progType {
	case ebpf.XDP, ebpf.SchedCLS:
		return true
	default:
		return false
	}
}

func runTestProgs(t *testing.T, inputValues inputValues, baseObjs *ebpf.Collection, pluginHooksObjs map[string]*ebpf.Collection) outputValues {
	t.Helper()

	outputs := outputValues{
		base:    map[string]int32{},
		hook:    map[string]map[string]int32{},
		returns: map[string]uint32{},
	}

	for name, val := range inputValues.base {
		require.NotNilf(t, baseObjs.Variables[name], "%s is not a variable", name)
		require.NoErrorf(t, baseObjs.Variables[name].Set(val), "setting %s", name)
	}

	for plugin, hookInputs := range inputValues.hook {
		objs := pluginHooksObjs[plugin]
		if objs == nil {
			continue
		}

		for name, val := range hookInputs {
			require.NoError(t, objs.Variables[name].Set(val))
		}
	}

	var tailCallEnabled bool
	if v := baseObjs.Variables["__config_tail_call_enabled"]; v != nil {
		var val int32
		_ = v.Get(&val)
		tailCallEnabled = (val != 0)
	}

	for name, prog := range baseObjs.Programs {
		if !supportsTestRun(prog.Type()) {
			continue
		}
		if strings.HasPrefix(name, preHookDispatcherProgPrefix) ||
			strings.HasPrefix(name, "relocated_") ||
			isPolicyProgram(name) {
			continue
		}
		if tailCallEnabled && !strings.HasSuffix(name, "_caller") {
			continue
		}
		if disp := baseObjs.Programs[preHookDispatcherProgPrefix+name]; disp != nil {
			prog = disp
		}
		ret, _, err := prog.Test(make([]byte, 14))
		require.NoErrorf(t, err, "running %s", name)
		var zeroKey uint32 = 0
		var zeroValue int32 = 0
		require.NoError(t, baseObjs.Maps["seq"].Update(&zeroKey, &zeroValue, 0))
		outputs.returns[name] = ret
	}

	for name, v := range baseObjs.Variables {
		var val int32
		if v.Size() == 1 {
			var boolVal bool
			require.NoErrorf(t, v.Get(&boolVal), "getting %s", name)
			if boolVal {
				val = 1
			}
		} else {
			require.NoErrorf(t, v.Get(&val), "getting %s", name)
		}
		outputs.base[name] = val
	}

	for plugin, objs := range pluginHooksObjs {
		if objs == nil {
			continue
		}

		pluginOutputs := map[string]int32{}

		for name, v := range objs.Variables {
			var val int32
			require.NoErrorf(t, v.Get(&val), "getting %s for plugin %s", name, plugin)
			pluginOutputs[name] = val
		}

		outputs.hook[plugin] = pluginOutputs
	}

	return outputs
}

func maybeReportVerifierError(err error) error {
	if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
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

	t.Run("tc", func(t *testing.T) {
		testPrivilegedHooksSpec(t, testprogs.LoadPluginsBase)
	})
	t.Run("xdp", func(t *testing.T) {
		testPrivilegedHooksSpec(t, testprogs.LoadPluginsBaseXdp)
	})
}

func testPrivilegedHooksSpec(t *testing.T, loadBase func() (*ebpf.CollectionSpec, error)) {
	t.Helper()

	preparePluginHooksSpec := func(baseColl *ebpf.Collection, hookColl *ebpf.CollectionSpec, hooks []*datapathplugins.InstrumentCollectionRequest_Hook) {
		usedHookPrograms := map[string]bool{}
		for _, hook := range hooks {
			hookProgramName := chooseHookProgram(hook)
			usedHookPrograms[hookProgramName] = true
			if hook.GetAttachTarget() != nil {
				hookColl.Programs[hookProgramName].AttachTarget = baseColl.Programs[hook.Target]
				hookColl.Programs[hookProgramName].AttachTo = hook.AttachTarget.SubprogName
			}
		}

		// prune any unused hook programs so they aren't loaded
		for name := range hookColl.Programs {
			if !usedHookPrograms[name] {
				delete(hookColl.Programs, name)
			}
		}
	}

	type hook struct {
		plugin    string
		terminate bool
	}

	testCases := []struct {
		name string
		pre  []hook
		post []hook

		hooks                                map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec
		inputValues                          inputValues
		expectedInstrumentCollectionRequests map[string]*datapathplugins.InstrumentCollectionRequest
		expectedOutputValues                 outputValues
	}{
		{
			name: "no hooks",
			pre:  []hook{},
			post: []hook{},
		},
		{
			name: "pre hooks basic",
			pre: []hook{
				{"plugin_a", false},
				{"plugin_b", false},
			},
			post: []hook{},
		},
		{
			name: "post hooks basic",
			pre:  []hook{},
			post: []hook{
				{"plugin_a", false},
				{"plugin_b", false},
			},
		},
		{
			name: "pre and post hooks basic",
			pre: []hook{
				{"plugin_a", false},
				{"plugin_b", false},
			},
			post: []hook{
				{"plugin_a", false},
				{"plugin_b", false},
			},
		},
		{
			name: "pre hook override",
			pre: []hook{
				{"plugin_a", true},
				{"plugin_b", false},
			},
			post: []hook{
				{"plugin_a", false},
				{"plugin_b", false},
			},
		},
		{
			name: "post hook override",
			pre: []hook{
				{"plugin_a", false},
				{"plugin_b", false},
			},
			post: []hook{
				{"plugin_a", true},
				{"plugin_b", false},
			},
		},
	}

	baseSpec, err := loadBase()
	require.NoError(t, err)
	hooksSpec, err := testprogs.LoadPluginsHooks()
	require.NoError(t, err)

	buildHooks := func(spec []hook, hookType datapathplugins.HookType, hooks map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec) {
		for i, p := range spec {
			var constraints []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint
			if i > 0 {
				constraints = append(constraints, &datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
					Plugin: spec[i-1].plugin,
					Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_AFTER,
				})
			}
			for prog, progSpec := range baseSpec.Programs {
				if isPolicyProgram(prog) {
					continue
				}
				if err := canInstrument(baseSpec, progSpec, hookType); err != nil {
					continue
				}
				hooks[p.plugin] = append(hooks[p.plugin], &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:        hookType,
					Target:      prog,
					Constraints: constraints,
				})
			}
		}
	}

	buildHookInputsAndOutputs := func(prog string, spec *ebpf.ProgramSpec,
		hooks []hook, pre bool, terminated bool, seq int32,
		inputs inputValues, outputs outputValues) bool {
		if !pre && bpf.IsTailCall(spec) {
			return terminated
		}
		for _, p := range hooks {
			seq++

			if inputs.hook[p.plugin] == nil {
				inputs.hook[p.plugin] = map[string]int32{}
			}
			if outputs.hook[p.plugin] == nil {
				outputs.hook[p.plugin] = map[string]int32{}
			}

			var prefix string
			if pre {
				prefix = "before"
			} else {
				prefix = "after"
			}

			hookProgName := fmt.Sprintf("%s_%s", prefix, prog)
			hookProgRet := fmt.Sprintf("%s_ret", hookProgName)
			hookProgSeq := fmt.Sprintf("%s_seq", hookProgName)
			hookProgRetParam := fmt.Sprintf("%s_ret_param", hookProgName)

			if !terminated && supportsTestRun(spec.Type) {
				outputs.hook[p.plugin][hookProgSeq] = seq
				if !pre {
					outputs.hook[p.plugin][hookProgRetParam] = 1
				}
			} else {
				outputs.hook[p.plugin][hookProgSeq] = 0
				if !pre {
					outputs.hook[p.plugin][hookProgRetParam] = 0
				}
			}

			if p.terminate || !supportsTestRun(spec.Type) {
				inputs.hook[p.plugin][hookProgRet] = 0
				outputs.hook[p.plugin][hookProgRet] = 0
				terminated = true
			} else {
				inputs.hook[p.plugin][hookProgRet] = retValProceed(spec)
				outputs.hook[p.plugin][hookProgRet] = retValProceed(spec)
			}
		}

		return terminated
	}

	buildInputsAndOutputs := func(pre []hook, post []hook) (inputValues, outputValues) {
		inputs := inputValues{
			base: map[string]int32{},
			hook: map[string]map[string]int32{},
		}
		outputs := outputValues{
			base:    map[string]int32{},
			returns: map[string]uint32{},
			hook:    map[string]map[string]int32{},
		}

		for prog, spec := range baseSpec.Programs {
			if isPolicyProgram(prog) {
				continue
			}
			var terminated bool

			terminated = buildHookInputsAndOutputs(prog, spec, pre,
				true, terminated, 0, inputs, outputs)
			seq := int32(0)
			if !terminated && supportsTestRun(spec.Type) {
				seq = int32(len(pre)) + 1
			}
			outputs.base[fmt.Sprintf("%s_seq", prog)] = seq
			terminated = buildHookInputsAndOutputs(prog, spec, post,
				false, terminated, int32(len(pre))+1, inputs, outputs)
			if supportsTestRun(spec.Type) {
				if terminated {
					outputs.returns[prog] = 0
				} else {
					outputs.returns[prog] = 1
				}
			}
		}

		for name := range baseSpec.Variables {
			if _, ok := outputs.base[name]; !ok {
				outputs.base[name] = 0
			}
		}

		for _, hooks := range outputs.hook {
			for name := range hooksSpec.Variables {
				if _, ok := hooks[name]; !ok {
					hooks[name] = 0
				}
			}
		}

		return inputs, outputs
	}

	buildInstrumentCollectionRequests := func(hooks map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec) map[string]*datapathplugins.InstrumentCollectionRequest {
		result := map[string]*datapathplugins.InstrumentCollectionRequest{}

		for plugin, hooks := range hooks {
			result[plugin] = &datapathplugins.InstrumentCollectionRequest{}
			for _, hook := range hooks {
				var attachTarget *datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget
				if !bpf.IsTailCall(baseSpec.Programs[hook.Target]) {
					var subprogName string
					if hook.Type == datapathplugins.HookType_PRE {
						subprogName = preHookSubprogName(plugin)
					} else {
						subprogName = postHookSubprogName(plugin)
					}
					attachTarget = &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
						SubprogName: subprogName,
					}
				}
				result[plugin].Hooks = append(result[plugin].Hooks, &datapathplugins.InstrumentCollectionRequest_Hook{
					AttachTarget: attachTarget,
					Type:         hook.Type,
					Target:       hook.Target,
				})
			}
		}

		return result
	}

	for i := range testCases {
		tc := &testCases[i]
		tc.hooks = map[string][]*datapathplugins.PrepareCollectionResponse_HookSpec{}
		buildHooks(tc.pre, datapathplugins.HookType_PRE, tc.hooks)
		buildHooks(tc.post, datapathplugins.HookType_POST, tc.hooks)
		tc.inputValues, tc.expectedOutputValues = buildInputsAndOutputs(tc.pre, tc.post)
		tc.expectedInstrumentCollectionRequests = buildInstrumentCollectionRequests(tc.hooks)
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
			baseSpec, err := loadBase()
			require.NoError(t, err)
			opts := &bpf.CollectionOptions{}
			instrumentCollectionRequests, hookSlots, err := hooksSpec.instrumentCollection(baseSpec, opts)
			require.NoError(t, err)
			for _, patch := range opts.CollectionPatches {
				require.NoError(t, patch(baseSpec))
			}
			for program, patches := range opts.ProgramPatches {
				for _, patch := range patches {
					baseSpec.Programs[program].Instructions, err = patch(baseSpec.Programs[program].Instructions)
					require.NoError(t, err)
				}
			}
			if diff := cmp.Diff(
				tc.expectedInstrumentCollectionRequests,
				instrumentCollectionRequests,
				protocmp.SortRepeated(func(a, b *datapathplugins.InstrumentCollectionRequest_Hook) bool {
					if a.Target == b.Target {
						return a.Type < b.Type
					}

					return a.Target < b.Target
				}),
				protocmp.Transform(),
			); diff != "" {
				t.Fatalf("instrumentCollectionRequests did not match what was expected (-want +got):\n%s", diff)
			}
			baseColl, err := ebpf.NewCollection(baseSpec)
			require.NoError(t, maybeReportVerifierError(err))
			defer baseColl.Close()
			for name, prog := range baseSpec.Programs {
				if strings.HasPrefix(name, preHookDispatcherProgPrefix) {
					continue
				}
				if bpf.IsTailCall(prog) && !isPolicyProgram(prog.Name) {
					slot, err := bpf.TailCallSlot(prog)
					require.NoError(t, err)
					require.NoError(t, baseColl.Maps["cilium_calls"].Put(slot, baseColl.Programs[name]))
				}
			}

			pluginHooksObjs := map[string]*ebpf.Collection{}

			for plugin, req := range instrumentCollectionRequests {
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
					if bpf.IsTailCall(baseSpec.Programs[hook.Target]) || isPolicyProgram(hook.Target) {
						err := baseColl.Maps["cilium_calls"].Put(hookSlots[hook], pluginHooks.Programs[chooseHookProgram(hook)])
						require.NoError(t, err)
						continue
					}
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

			outputs := runTestProgs(t, tc.inputValues, baseColl, pluginHooksObjs)
			if diff := cmp.Diff(
				tc.expectedOutputValues,
				outputs,
				cmp.AllowUnexported(outputValues{}),
			); diff != "" {
				t.Fatalf("outputs did not match what was expected (-want +got):\n%s", diff)
			}
		})
	}
}

type fakePluginRegistry map[string]*fakePlugin

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
		if h.GetAttachTarget() != nil {
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

	baseSpec, err := testprogs.LoadPluginsBase()
	require.NoError(t, err)

	baseCollSpec := &datapathplugins.PrepareCollectionRequest_CollectionSpec{
		Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{},
		Maps:     map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{},
	}

	baseColl := &datapathplugins.InstrumentCollectionRequest_Collection{
		Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{},
		Maps:     map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{},
	}

	for name, p := range baseSpec.Programs {
		baseCollSpec.Programs[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
			License:     p.License,
			SectionName: p.SectionName,
			Type:        uint32(p.Type),
			AttachType:  uint32(p.AttachType),
		}
		if !strings.Contains(name, "_tail_") {
			baseColl.Programs[name] = &datapathplugins.InstrumentCollectionRequest_Collection_Program{}
		}
	}
	for name, m := range baseSpec.Maps {
		if m.Type != ebpf.ProgramArray {
			baseColl.Maps[name] = &datapathplugins.InstrumentCollectionRequest_Collection_Map{}

			continue
		}
		baseCollSpec.Maps[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
			Flags:      m.Flags,
			KeySize:    m.KeySize,
			MaxEntries: m.MaxEntries,
			Type:       uint32(m.Type),
			ValueSize:  m.ValueSize,
		}
	}

	prepareHooksReqFor := func(spec *ebpf.CollectionSpec) *datapathplugins.PrepareCollectionRequest {
		specReq := &datapathplugins.PrepareCollectionRequest_CollectionSpec{
			Programs: map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{},
			Maps:     map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{},
		}
		for name, p := range spec.Programs {
			specReq.Programs[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
				License:     p.License,
				SectionName: p.SectionName,
				Type:        uint32(p.Type),
				AttachType:  uint32(p.AttachType),
			}
		}
		for name, m := range spec.Maps {
			specReq.Maps[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
				Flags:      m.Flags,
				KeySize:    m.KeySize,
				MaxEntries: m.MaxEntries,
				Type:       uint32(m.Type),
				ValueSize:  m.ValueSize,
			}
		}
		return &datapathplugins.PrepareCollectionRequest{
			Collection:        specReq,
			AttachmentContext: &datapathplugins.AttachmentContext{},
		}
	}

	baseCollFor := func(spec *ebpf.CollectionSpec) *datapathplugins.InstrumentCollectionRequest_Collection {
		coll := &datapathplugins.InstrumentCollectionRequest_Collection{
			Programs: map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program{},
			Maps:     map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map{},
		}
		for name := range spec.Programs {
			coll.Programs[name] = &datapathplugins.InstrumentCollectionRequest_Collection_Program{}
		}
		for name := range spec.Maps {
			coll.Maps[name] = &datapathplugins.InstrumentCollectionRequest_Collection_Map{}
		}
		return coll
	}

	prepareHooksReq := prepareHooksReqFor(baseSpec)

	hookSpec := func(typ datapathplugins.HookType,
		target string,
		constraints []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint) *datapathplugins.PrepareCollectionResponse_HookSpec {
		return &datapathplugins.PrepareCollectionResponse_HookSpec{
			Type:        typ,
			Target:      target,
			Constraints: constraints,
		}
	}

	pre := func(target string, constraints ...*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint) *datapathplugins.PrepareCollectionResponse_HookSpec {
		return hookSpec(datapathplugins.HookType_PRE, target, constraints)
	}

	post := func(target string, constraints ...*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint) *datapathplugins.PrepareCollectionResponse_HookSpec {
		return hookSpec(datapathplugins.HookType_POST, target, constraints)
	}

	before := func(plugin string) *datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint {
		return &datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint{
			Plugin: plugin,
			Order:  datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE,
		}
	}

	pluginAPrepareHooksResp := &datapathplugins.PrepareCollectionResponse{
		Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
			pre("program_tc", before("plugin_b")),
			post("program_tc", before("plugin_b")),
			pre("program_xdp", before("plugin_b")),
			post("program_xdp", before("plugin_b")),
		},
		Cookie: "plugin_a_cookie",
	}

	pluginBPrepareHooksResp := &datapathplugins.PrepareCollectionResponse{
		Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
			pre("program_tc"),
			post("program_tc"),
			pre("program_xdp"),
			post("program_xdp"),
		},
		Cookie: "plugin_b_cookie",
	}

	loadHooksReq := func(plugin string) *datapathplugins.InstrumentCollectionRequest {
		return &datapathplugins.InstrumentCollectionRequest{
			Collection:        baseColl,
			AttachmentContext: &datapathplugins.AttachmentContext{},
			Hooks: []*datapathplugins.InstrumentCollectionRequest_Hook{
				{
					Type:   datapathplugins.HookType_PRE,
					Target: "program_tc",
					AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
						SubprogName: preHookSubprogName(plugin),
					},
				},
				{
					Type:   datapathplugins.HookType_POST,
					Target: "program_tc",
					AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
						SubprogName: postHookSubprogName(plugin),
					},
				},
				{
					Type:   datapathplugins.HookType_PRE,
					Target: "program_xdp",
					AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
						SubprogName: preHookSubprogName(plugin),
					},
				},
				{
					Type:   datapathplugins.HookType_POST,
					Target: "program_xdp",
					AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
						SubprogName: postHookSubprogName(plugin),
					},
				},
			},
			Cookie: fmt.Sprintf("%s_cookie", plugin),
		}
	}

	loadTailHooksReq := func(plugin string, resp *datapathplugins.PrepareCollectionResponse, spec *ebpf.CollectionSpec) *datapathplugins.InstrumentCollectionRequest {
		if spec == nil {
			spec = baseSpec
		}
		coll := baseCollFor(spec)
		hasPolicyHook := false
		for _, h := range resp.Hooks {
			if isPolicyProgram(h.Target) {
				hasPolicyHook = true
				break
			}
		}
		if !hasPolicyHook {
			delete(coll.Maps, "cilium_call_policy")
		}
		progs := make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program)
		maps.Copy(progs, coll.Programs)

		var hooks []*datapathplugins.InstrumentCollectionRequest_Hook
		for _, hookSpec := range resp.Hooks {
			p := spec.Programs[hookSpec.Target]
			isTail := (p != nil && (bpf.IsTailCall(p) || isPolicyProgram(p.Name)))

			var attachTarget *datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget
			if isTail {
				if isPolicyProgram(hookSpec.Target) {
					progs["relocated_"+hookSpec.Target] = &datapathplugins.InstrumentCollectionRequest_Collection_Program{}
				} else {
					progs[preHookDispatcherProgPrefix+hookSpec.Target] = &datapathplugins.InstrumentCollectionRequest_Collection_Program{}
				}
			} else {
				subprog := preHookSubprogName(plugin)
				if hookSpec.Type == datapathplugins.HookType_POST {
					subprog = postHookSubprogName(plugin)
				}
				attachTarget = &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
					SubprogName: subprog,
				}
			}

			hooks = append(hooks, &datapathplugins.InstrumentCollectionRequest_Hook{
				Type:         hookSpec.Type,
				Target:       hookSpec.Target,
				AttachTarget: attachTarget,
			})
		}

		return &datapathplugins.InstrumentCollectionRequest{
			Collection: &datapathplugins.InstrumentCollectionRequest_Collection{
				Programs: progs,
				Maps:     coll.Maps,
			},
			AttachmentContext: &datapathplugins.AttachmentContext{},
			Hooks:             hooks,
			Cookie:            resp.Cookie,
		}
	}

	type testConfig struct {
		TailCallEnabled     int32 `config:"tail_call_enabled"`
		PolicyCallerEnabled int32 `config:"policy_caller_enabled"`
	}

	testCases := []struct {
		name                 string
		baseSpec             func() (*ebpf.CollectionSpec, error)
		inputValues          inputValues
		attachmentPolicies   map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
		transactions         map[string]transaction
		expectedOutputValues outputValues
		expectedErr          error
		config               testConfig
	}{
		{
			name:     "pre and post hooks basic",
			baseSpec: testprogs.LoadPluginsBase,
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginAPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_a"),
					loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginBPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_b"),
					loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tc_ret":  -1,
						"after_program_tc_ret":   -1,
						"before_program_xdp_ret": -1,
						"after_program_xdp_ret":  -1,
					},
					"plugin_b": {
						"before_program_tc_ret":  -1,
						"after_program_tc_ret":   -1,
						"before_program_xdp_ret": -1,
						"after_program_xdp_ret":  -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_tc_seq":            3,
					"program_xdp_seq":           3,
					"program_tc_caller_seq":     1,
					"program_policy_caller_seq": 1,
					"program_tail_tc_seq":       0,
				},
				returns: map[string]uint32{
					"program_tc":            1,
					"program_xdp":           1,
					"program_tc_caller":     1,
					"program_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tc_seq":       1,
						"before_program_tc_ret":       -1,
						"after_program_tc_seq":        4,
						"after_program_tc_ret":        -1,
						"after_program_tc_ret_param":  1,
						"before_program_xdp_seq":      1,
						"before_program_xdp_ret":      -1,
						"after_program_xdp_seq":       4,
						"after_program_xdp_ret":       -1,
						"after_program_xdp_ret_param": 1,
					},
					"plugin_b": {
						"before_program_tc_seq":       2,
						"before_program_tc_ret":       -1,
						"after_program_tc_seq":        5,
						"after_program_tc_ret":        -1,
						"after_program_tc_ret_param":  1,
						"before_program_xdp_seq":      2,
						"before_program_xdp_ret":      -1,
						"after_program_xdp_seq":       5,
						"after_program_xdp_ret":       -1,
						"after_program_xdp_ret_param": 1,
					},
				},
			},
		},
		{
			name:     "plugin_b returns an error in PrepareCollection() with AttachmentPolicyAlways",
			baseSpec: testprogs.LoadPluginsBase,
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginAPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_a"),
					loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: prepareHooksReq,
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
			name:     "plugin_b returns an error in PrepareCollection() with AttachmentPolicyBestEffort",
			baseSpec: testprogs.LoadPluginsBase,
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginAPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_a"),
					loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq: prepareHooksReq,
					prepareHooksErr: errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyBestEffort,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tc_ret":  -1,
						"after_program_tc_ret":   -1,
						"before_program_xdp_ret": -1,
						"after_program_xdp_ret":  -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_tc_seq":            2,
					"program_xdp_seq":           2,
					"program_tc_caller_seq":     1,
					"program_policy_caller_seq": 1,
					"program_tail_tc_seq":       0,
				},
				returns: map[string]uint32{
					"program_tc":            1,
					"program_xdp":           1,
					"program_tc_caller":     1,
					"program_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tc_seq":       1,
						"before_program_tc_ret":       -1,
						"after_program_tc_seq":        3,
						"after_program_tc_ret":        -1,
						"after_program_tc_ret_param":  1,
						"before_program_xdp_seq":      1,
						"before_program_xdp_ret":      -1,
						"after_program_xdp_seq":       3,
						"after_program_xdp_ret":       -1,
						"after_program_xdp_ret_param": 1,
					},
				},
			},
		},
		{
			name:     "plugin_b returns an error in InstrumentCollection() with AttachmentPolicyAlways",
			baseSpec: testprogs.LoadPluginsBase,
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginAPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_a"),
					loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginBPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_b"),
					loadHooksErr:     errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			expectedErr: errors.New("some error"),
		},
		{
			name:     "plugin_b returns an error in InstrumentCollection() with AttachmentPolicyBestEffort",
			baseSpec: testprogs.LoadPluginsBase,
			transactions: map[string]transaction{
				"plugin_a": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginAPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_a"),
					loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
				},
				"plugin_b": {
					prepareHooksReq:  prepareHooksReq,
					prepareHooksResp: pluginBPrepareHooksResp,
					loadHooksReq:     loadHooksReq("plugin_b"),
					loadHooksErr:     errors.New("some error"),
				},
			},
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyBestEffort,
			},
			expectedErr: errors.New("some error"),
		},
		{
			name:     "chained pre hooks on tc tail call target",
			baseSpec: testprogs.LoadPluginsBase,
			config: testConfig{
				TailCallEnabled: 1,
			},
			transactions: func() map[string]transaction {
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_tc", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_tc"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_tc_ret": -1,
					},
					"plugin_b": {
						"before_program_tail_tc_ret": -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_tc_caller_seq":      1,
					"program_policy_caller_seq":  1,
					"program_tail_tc_seq":        4,
					"__config_tail_call_enabled": 1,
				},
				returns: map[string]uint32{
					"program_tc_caller":     1,
					"program_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_tc_seq": 2,
						"before_program_tail_tc_ret": -1,
					},
					"plugin_b": {
						"before_program_tail_tc_seq": 3,
						"before_program_tail_tc_ret": -1,
					},
				},
			},
		},
		{
			name:     "chained pre hooks on xdp tail call target",
			baseSpec: testprogs.LoadPluginsBaseXdp,
			config: testConfig{
				TailCallEnabled: 1,
			},
			transactions: func() map[string]transaction {
				spec, _ := testprogs.LoadPluginsBaseXdp()
				pReq := prepareHooksReqFor(spec)
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_xdp", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_xdp"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_xdp_ret": -1,
					},
					"plugin_b": {
						"before_program_tail_xdp_ret": -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_xdp_caller_seq":        1,
					"program_tail_xdp_seq":          4,
					"program_xdp_policy_caller_seq": 1,
					"__config_tail_call_enabled":    1,
				},
				returns: map[string]uint32{
					"program_xdp_caller":        1,
					"program_xdp_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_xdp_seq": 2,
						"before_program_tail_xdp_ret": -1,
					},
					"plugin_b": {
						"before_program_tail_xdp_seq": 3,
						"before_program_tail_xdp_ret": -1,
					},
				},
			},
		},
		{
			name:     "pre hooks on entrypoint and tc tail call target",
			baseSpec: testprogs.LoadPluginsBase,
			config:   testConfig{TailCallEnabled: 1},
			transactions: func() map[string]transaction {
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tc_caller", before("plugin_b")),
						pre("program_tail_tc", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tc_caller"),
						pre("program_tail_tc"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tc_caller_ret": -1,
						"before_program_tail_tc_ret":   -1,
					},
					"plugin_b": {
						"before_program_tc_caller_ret": -1,
						"before_program_tail_tc_ret":   -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_tc_caller_seq":      3,
					"program_policy_caller_seq":  1,
					"program_tail_tc_seq":        6,
					"__config_tail_call_enabled": 1,
				},
				returns: map[string]uint32{
					"program_tc_caller":     1,
					"program_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tc_caller_seq": 1,
						"before_program_tc_caller_ret": -1,
						"before_program_tail_tc_seq":   4,
						"before_program_tail_tc_ret":   -1,
					},
					"plugin_b": {
						"before_program_tc_caller_seq": 2,
						"before_program_tc_caller_ret": -1,
						"before_program_tail_tc_seq":   5,
						"before_program_tail_tc_ret":   -1,
					},
				},
			},
		},
		{
			name:     "pre hooks on entrypoint and xdp tail call target",
			baseSpec: testprogs.LoadPluginsBaseXdp,
			config:   testConfig{TailCallEnabled: 1},
			transactions: func() map[string]transaction {
				spec, _ := testprogs.LoadPluginsBaseXdp()
				pReq := prepareHooksReqFor(spec)
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_xdp_caller", before("plugin_b")),
						pre("program_tail_xdp", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_xdp_caller"),
						pre("program_tail_xdp"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_xdp_caller_ret": -1,
						"before_program_tail_xdp_ret":   -1,
					},
					"plugin_b": {
						"before_program_xdp_caller_ret": -1,
						"before_program_tail_xdp_ret":   -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_xdp_caller_seq":        3,
					"program_tail_xdp_seq":          6,
					"program_xdp_policy_caller_seq": 1,
					"__config_tail_call_enabled":    1,
				},
				returns: map[string]uint32{
					"program_xdp_caller":        1,
					"program_xdp_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_xdp_caller_seq": 1,
						"before_program_xdp_caller_ret": -1,
						"before_program_tail_xdp_seq":   4,
						"before_program_tail_xdp_ret":   -1,
					},
					"plugin_b": {
						"before_program_xdp_caller_seq": 2,
						"before_program_xdp_caller_ret": -1,
						"before_program_tail_xdp_seq":   5,
						"before_program_tail_xdp_ret":   -1,
					},
				},
			},
		},
		{
			name:     "short-circuiting in pre hook on tc tail call target",
			baseSpec: testprogs.LoadPluginsBase,
			config:   testConfig{TailCallEnabled: 1},
			transactions: func() map[string]transaction {
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_tc", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_tc"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_tc_ret": 0,
					},
					"plugin_b": {
						"before_program_tail_tc_ret": -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_tc_caller_seq":      1,
					"program_policy_caller_seq":  1,
					"program_tail_tc_seq":        0,
					"__config_tail_call_enabled": 1,
				},
				returns: map[string]uint32{
					"program_tc_caller":     0,
					"program_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_tc_seq": 2,
						"before_program_tail_tc_ret": 0,
					},
					"plugin_b": {
						"before_program_tail_tc_seq": 0,
						"before_program_tail_tc_ret": -1,
					},
				},
			},
		},
		{
			name:     "short-circuiting in pre hook on xdp tail call target",
			baseSpec: testprogs.LoadPluginsBaseXdp,
			config:   testConfig{TailCallEnabled: 1},
			transactions: func() map[string]transaction {
				spec, _ := testprogs.LoadPluginsBaseXdp()
				pReq := prepareHooksReqFor(spec)
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_xdp", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("program_tail_xdp"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_xdp_ret": 1,
					},
					"plugin_b": {
						"before_program_tail_xdp_ret": -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_xdp_caller_seq":        1,
					"program_tail_xdp_seq":          0,
					"program_xdp_policy_caller_seq": 1,
					"__config_tail_call_enabled":    1,
				},
				returns: map[string]uint32{
					"program_xdp_caller":        1,
					"program_xdp_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_program_tail_xdp_seq": 2,
						"before_program_tail_xdp_ret": 1,
					},
					"plugin_b": {
						"before_program_tail_xdp_seq": 0,
						"before_program_tail_xdp_ret": -1,
					},
				},
			},
		},
		{
			name:     "pre hooks on policy program",
			baseSpec: testprogs.LoadPluginsBase,
			config: testConfig{
				TailCallEnabled:     1,
				PolicyCallerEnabled: 1,
			},
			transactions: func() map[string]transaction {
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("cil_lxc_policy", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("cil_lxc_policy"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  prepareHooksReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, baseSpec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_cil_lxc_policy_ret": -1,
					},
					"plugin_b": {
						"before_cil_lxc_policy_ret": -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_tc_caller_seq":          1,
					"program_tail_tc_seq":            2,
					"program_policy_caller_seq":      1,
					"cil_lxc_policy_seq":             4,
					"__config_tail_call_enabled":     1,
					"__config_policy_caller_enabled": 1,
				},
				returns: map[string]uint32{
					"program_tc_caller":     1,
					"program_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_cil_lxc_policy_seq": 2,
						"before_cil_lxc_policy_ret": -1,
					},
					"plugin_b": {
						"before_cil_lxc_policy_seq": 3,
						"before_cil_lxc_policy_ret": -1,
					},
				},
			},
		},
		{
			name:     "pre hooks on xdp policy program",
			baseSpec: testprogs.LoadPluginsBaseXdp,
			config: testConfig{
				TailCallEnabled:     1,
				PolicyCallerEnabled: 1,
			},
			transactions: func() map[string]transaction {
				spec, _ := testprogs.LoadPluginsBaseXdp()
				pReq := prepareHooksReqFor(spec)
				respA := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_a_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("cil_lxc_policy_egress", before("plugin_b")),
					},
				}
				respB := &datapathplugins.PrepareCollectionResponse{
					Cookie: "plugin_b_cookie",
					Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
						pre("cil_lxc_policy_egress"),
					},
				}
				return map[string]transaction{
					"plugin_a": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respA,
						loadHooksReq:     loadTailHooksReq("plugin_a", respA, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
					"plugin_b": {
						prepareHooksReq:  pReq,
						prepareHooksResp: respB,
						loadHooksReq:     loadTailHooksReq("plugin_b", respB, spec),
						loadHooksResp:    &datapathplugins.InstrumentCollectionResponse{},
					},
				}
			}(),
			attachmentPolicies: map[string]api_v2alpha1.CiliumDatapathPluginAttachmentPolicy{
				"plugin_a": api_v2alpha1.AttachmentPolicyAlways,
				"plugin_b": api_v2alpha1.AttachmentPolicyAlways,
			},
			inputValues: inputValues{
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_cil_lxc_policy_egress_ret": -1,
					},
					"plugin_b": {
						"before_cil_lxc_policy_egress_ret": -1,
					},
				},
			},
			expectedOutputValues: outputValues{
				base: map[string]int32{
					"program_xdp_caller_seq":         1,
					"program_tail_xdp_seq":           2,
					"program_xdp_policy_caller_seq":  1,
					"cil_lxc_policy_egress_seq":      4,
					"__config_tail_call_enabled":     1,
					"__config_policy_caller_enabled": 1,
				},
				returns: map[string]uint32{
					"program_xdp_caller":        1,
					"program_xdp_policy_caller": 1,
				},
				hook: map[string]map[string]int32{
					"plugin_a": {
						"before_cil_lxc_policy_egress_seq": 2,
						"before_cil_lxc_policy_egress_ret": -1,
					},
					"plugin_b": {
						"before_cil_lxc_policy_egress_seq": 3,
						"before_cil_lxc_policy_egress_ret": -1,
					},
				},
			},
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

			l := newBPFCollectionLoader(true, bpffsPluginsOperationsDir(tmp))

			require.NotNil(t, tc.baseSpec, "baseSpec must be explicitly specified for test case %s", tc.name)
			spec, err := tc.baseSpec()
			require.NoError(t, err)

			pinsDir := filepath.Join(tmp, "pins_dir")
			baseColl, commit, cleanup, err := l.Load(
				t.Context(),
				logger,
				spec,
				&bpf.CollectionOptions{
					Constants: tc.config,
				},
				&config.Config{
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
			for name, p := range baseColl.Programs {
				if isPolicyProgram(name) {
					if m := baseColl.Maps["cilium_call_policy"]; m != nil {
						require.NoError(t, m.Update(uint32(42), uint32(p.FD()), ebpf.UpdateAny))
					}
				}
			}
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

			// Fill in the blanks
			pluginHooksObjs := map[string]*ebpf.Collection{}
			for name, plugin := range plugins {
				pluginHooksObjs[name] = plugin.coll

				if tc.expectedOutputValues.hook[name] != nil {
					for varName := range plugin.coll.Variables {
						if _, ok := tc.expectedOutputValues.hook[name][varName]; !ok {
							tc.expectedOutputValues.hook[name][varName] = 0
						}
					}
				}
			}
			for name := range baseColl.Variables {
				if _, ok := tc.expectedOutputValues.base[name]; !ok {
					tc.expectedOutputValues.base[name] = 0
				}
			}

			outputs := runTestProgs(t, tc.inputValues, baseColl, pluginHooksObjs)
			if diff := cmp.Diff(
				tc.expectedOutputValues,
				outputs,
				cmp.AllowUnexported(outputValues{}),
			); diff != "" {
				t.Errorf("outputs did not match what was expected (-want +got):\n%s", diff)
			}
		})
	}
}
