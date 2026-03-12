// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/cilium/cilium/api/v1/datapathplugins"
)

func preHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__pre_hook_%s__", pluginName)
}

func postHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__post_hook_%s__", pluginName)
}

// hooksSpec tracks inter-plugin dependencies and applies them to instrument
// programs in BPF collections with appropriate dispatchers.
type hooksSpec struct {
	hooks map[string]map[datapathplugins.HookType]*pluginDependencyGraph
}

func newHooksSpec() *hooksSpec {
	return &hooksSpec{
		hooks: make(map[string]map[datapathplugins.HookType]*pluginDependencyGraph),
	}
}

// hook returns the plugin dependency graph for the hook point indicated by
// (target, hookType). Consumers can then add constraints or plugins to this
// dependency graph.
func (hs *hooksSpec) hook(target string, hookType datapathplugins.HookType) *pluginDependencyGraph {
	if hs.hooks[target] == nil {
		hs.hooks[target] = map[datapathplugins.HookType]*pluginDependencyGraph{
			datapathplugins.HookType_PRE:  {},
			datapathplugins.HookType_POST: {},
		}
	}

	return hs.hooks[target][hookType]
}

// instrumentCollection prepares an InstrumentCollectionRequest for each plugin
// that requested hooks and generates a program patch for each program that
// requires instrumentation. It doesn't patch program instructions directly.
// Patching is instead deferred until after reachability analysis and pruning
// happen.
func (hs *hooksSpec) instrumentCollection(cs *ebpf.CollectionSpec) (map[string]*datapathplugins.InstrumentCollectionRequest, map[string]func(asm.Instructions) (asm.Instructions, error), error) {
	var err error

	hooks := make(map[string]*datapathplugins.InstrumentCollectionRequest)
	programPatches := make(map[string]func(asm.Instructions) (asm.Instructions, error))

	for hookTarget, hookTypes := range hs.hooks {
		pre, sortErr := hookTypes[datapathplugins.HookType_PRE].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_PRE, sortErr))

			continue
		}
		post, sortErr := hookTypes[datapathplugins.HookType_POST].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_POST, sortErr))

			continue
		}
		patch, patchErr := hs.instrumentProgram(cs.Programs[hookTarget], pre, post, hooks)
		if patchErr != nil {
			err = errors.Join(err, fmt.Errorf("instrumenting %s: %w", hookTarget, patchErr))

			continue
		}
		programPatches[hookTarget] = patch
	}

	return hooks, programPatches, err
}

// instrumentProgram generates a program patcher that prepends a dispatcher that
// invokes pre-program hooks, then invokes the original program, and finally
// invokes post-program hooks. Something like this:
//
//	int dispatch(void *ctx) {
//	    int orig_ret, ret;
//
//	    ret = __pre_hook_plugin_a__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ret = __pre_hook_plugin_b__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ...
//	    orig_ret = original_cilium_prog(ctx);
//	    ...
//	    ret = __post_hook_plugin_a__(ctx, orig_ret);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ret = __post_hook_plugin_b__(ctx, orig_ret);
//	    if (ret != RET_PROCEED)
//	        return ret;
//
//	    return orig_ret;
//	}
//
//	int original_cilium_prog(void *ctx) {
//	    ...
//	}
//
//	int __pre_hook_plugin_a__(void *ctx) {
//	    volatile int ret = RET_PROCEED;
//	    return ret;
//	}
//
//	int __pre_hook_plugin_b__(void *ctx) {
//	    volatile int ret = RET_PROCEED;
//	    return ret;
//	}
//
//	int __post_hook_plugin_a__(void *ctx, int orig_ret) {
//	    volatile int ret = RET_PROCEED;
//	    return ret;
//	}
//
//	int __post_hook_plugin_a__(void *ctx, int orig_ret) {
//	    volatile int ret = RET_PROCEED;
//	    return ret;
//	}
func (hs *hooksSpec) instrumentProgram(ps *ebpf.ProgramSpec, pre []string, post []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest) (func(asm.Instructions) (asm.Instructions, error), error) {
	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return nil, fmt.Errorf("unable to extract function BTF info for target program")
	}

	var prologue asm.Instructions

	// Preserve ctx in R6, callee saved register.
	prologue = append(prologue, asm.Mov.Reg(asm.R6, asm.R1))

	for _, plugin := range pre {
		// ret = __pre_hook_xxx__(ctx);
		// if (ret != RET_VAL_PROCEED)
		//     return ret;
		subprogName := preHookSubprogName(plugin)
		prologue = append(prologue,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Call.Label(subprogName),
			asm.JNE.Imm32(asm.R0, retValProceed(ps), "return"),
		)
		if hooks[plugin] == nil {
			hooks[plugin] = &datapathplugins.InstrumentCollectionRequest{}
		}
		hooks[plugin].Hooks = append(hooks[plugin].Hooks, &datapathplugins.InstrumentCollectionRequest_Hook{
			AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
				SubprogName: subprogName,
			},
			Type:   datapathplugins.HookType_PRE,
			Target: ps.Name,
		})
	}

	// orig_ret = original_cilium_prog(ctx);
	prologue = append(prologue,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Call.Label(btfMeta.Name),
		asm.Mov.Reg(asm.R7, asm.R0),
	)

	for _, plugin := range post {
		// ret = __post_hook_xxx__(ctx, orig_ret);
		// if (ret != RET_VAL_PROCEED)
		//     return ret;
		subprogName := postHookSubprogName(plugin)
		prologue = append(prologue,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R7),
			asm.Call.Label(subprogName),
			asm.JNE.Imm32(asm.R0, retValProceed(ps), "return"),
		)
		if hooks[plugin] == nil {
			hooks[plugin] = &datapathplugins.InstrumentCollectionRequest{}
		}
		hooks[plugin].Hooks = append(hooks[plugin].Hooks, &datapathplugins.InstrumentCollectionRequest_Hook{
			AttachTarget: &datapathplugins.InstrumentCollectionRequest_Hook_AttachTarget{
				SubprogName: subprogName,
			},
			Type:   datapathplugins.HookType_POST,
			Target: ps.Name,
		})
	}

	prologue = append(prologue, asm.Mov.Reg(asm.R0, asm.R7))
	prologue = append(prologue, clampAndReturn(ps, "return")...)

	entryName := fmt.Sprintf("__%s__", btfMeta.Name)
	prologue[0] = btf.WithFuncMetadata(
		prologue[0].
			WithSymbol(entryName).
			WithSource(asm.Comment(entryName)),
		&btf.Func{
			Name:    entryName,
			Type:    funcProto,
			Linkage: btf.GlobalFunc,
			Tags:    btfMeta.Tags,
		})

	var epilogue asm.Instructions

	postHookProto := *funcProto
	postHookProto.Params = append(
		append([]btf.FuncParam(nil), postHookProto.Params...),
		btf.FuncParam{Name: "ret", Type: funcProto.Return},
	)

	for _, plugin := range pre {
		hookName := preHookSubprogName(plugin)
		epilogue = append(epilogue, freplaceSubProg(hookName, funcProto, ps)...)
	}
	for _, plugin := range post {
		hookName := postHookSubprogName(plugin)
		epilogue = append(epilogue, freplaceSubProg(hookName, &postHookProto, ps)...)
	}

	return func(insns asm.Instructions) (asm.Instructions, error) {
		return append(prologue, append(insns, epilogue...)...), nil
	}, nil
}

func freplaceSubProg(name string, funcProto *btf.FuncProto, ps *ebpf.ProgramSpec) asm.Instructions {
	var prog asm.Instructions

	if ps.Type == ebpf.SchedCLS || ps.Type == ebpf.SchedACT || ps.Type == ebpf.XDP {
		// To allow plugin programs to modify packet data, the freplace
		// subprogram must also modify packet data; otherwise,
		// verification fails with "Extension program changes packet
		// data, while original does not"
		//
		// https://github.com/torvalds/linux/blob/6596a02b207886e9e00bb0161c7fd59fea53c081/kernel/bpf/verifier.c#L19210
		//
		// The opposite is not true; it is OK if the plugin program
		// doesn't modify packet data while the freplace subprogram
		// does, so always call bpf_xdp_adjust_head or
		// bpf_skb_change_head to satisfy this condition, two helpers
		// that match the check in bpf_helper_changes_pkt_data:
		//
		// https://github.com/torvalds/linux/blob/2e68039281932e6dc37718a1ea7cbb8e2cda42e6/net/core/filter.c#L8097
		if ps.Type == ebpf.XDP {
			prog = append(prog,
				asm.Mov.Imm(asm.R2, 0),
				asm.FnXdpAdjustHead.Call(),
			)
		} else {
			prog = append(prog,
				asm.Mov.Imm(asm.R2, 0),
				asm.Mov.Imm(asm.R3, 0),
				asm.FnSkbChangeHead.Call(),
			)
		}
	}

	prog = append(prog,
		asm.Mov.Imm(asm.R0, retValProceed(ps)),
		asm.Return(),
	)

	prog[0] = btf.WithFuncMetadata(
		prog[0].WithSymbol(name).WithSource(asm.Comment(name)),
		&btf.Func{
			Name: name,
			Type: funcProto,
			// BTF_FUNC_GLOBAL ensures programs are independently verified.
			Linkage: btf.GlobalFunc,
		})

	return prog
}

func retValProceed(ps *ebpf.ProgramSpec) int32 {
	switch ps.AttachType {
	case ebpf.AttachCGroupInet4Bind, ebpf.AttachCGroupInet6Bind,
		ebpf.AttachCGroupUDP4Recvmsg, ebpf.AttachCGroupUDP6Recvmsg,
		ebpf.AttachCgroupInet4GetPeername, ebpf.AttachCgroupInet6GetPeername,
		ebpf.AttachCgroupInet4GetSockname, ebpf.AttachCgroupInet6GetSockname,
		ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupInet6Connect,
		ebpf.AttachCGroupInet4PostBind, ebpf.AttachCGroupInet6PostBind,
		ebpf.AttachCGroupUDP4Sendmsg, ebpf.AttachCGroupUDP6Sendmsg,
		ebpf.AttachCgroupInetSockRelease:
		return 1 // SYS_PROCEED
	default:
		return -1 // TCX_NEXT / TC_ACT_UNSPEC
	}
}

// clampAndReturn makes sure the verifier's return value range check is
// satisfied for certain attach types before exiting.
//
// https://github.com/torvalds/linux/blob/8a30aeb0d1b4e4aaf7f7bae72f20f2ae75385ccb/kernel/bpf/verifier.c#L17901
func clampAndReturn(ps *ebpf.ProgramSpec, label string) asm.Instructions {
	var defaultVal int64
	var min, max int32

	switch ps.AttachType {
	case ebpf.AttachCGroupInet4Bind, ebpf.AttachCGroupInet6Bind:
		min, max, defaultVal = 0, 3, 0
	case ebpf.AttachCGroupUDP4Recvmsg, ebpf.AttachCGroupUDP6Recvmsg,
		ebpf.AttachCgroupInet4GetPeername, ebpf.AttachCgroupInet6GetPeername,
		ebpf.AttachCgroupInet4GetSockname, ebpf.AttachCgroupInet6GetSockname:
		min, max, defaultVal = 1, 1, 1
	case ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupInet6Connect,
		ebpf.AttachCGroupInet4PostBind, ebpf.AttachCGroupInet6PostBind,
		ebpf.AttachCGroupUDP4Sendmsg, ebpf.AttachCGroupUDP6Sendmsg,
		ebpf.AttachCgroupInetSockRelease:
		min, max, defaultVal = 0, 1, 0
	default:
		return []asm.Instruction{
			asm.Return().WithSymbol(label),
		}
	}

	// Note: this structure is a more natural way to do a range check, but
	// for some reason on RHEL 8.10 kernels the verifier fails to realize
	// that the return value range has been clamped and fails anyway:
	//
	// asm.JGT.Imm(asm.R0, max, "set_default").WithSymbol(label),
	// asm.JLT.Imm(asm.R0, min, "set_default"),
	// asm.Ja.Label("exit"),
	// asm.LoadImm(asm.R0, defaultVal, asm.DWord).WithSymbol("set_default"),
	// asm.Return().WithSymbol("exit"),
	//
	// Doing an equality check for each value in the range [min, max] works
	// on all kernels and is only less efficient for bind4|6 programs where
	// the return value range is [0, 3]. It doesn't really matter though,
	// since bind() isn't a fast path operation.
	var insns []asm.Instruction
	for v := min; v <= max; v++ {
		insns = append(insns, asm.JEq.Imm(asm.R0, v, "exit"))
	}
	insns[0] = insns[0].WithSymbol(label)

	return append(insns,
		asm.LoadImm(asm.R0, defaultVal, asm.DWord),
		asm.Return().WithSymbol("exit"),
	)
}

type node struct {
	exists        bool
	outgoing      map[string]struct{}
	incomingCount int
}

// a pluginDependencyGraph is a DAG that tracks dependencies between plugins for
// a particular hook point.
type pluginDependencyGraph map[string]*node

// sort performs a topological sort that respects all ordering constraints. It
// consumes g in the process.
func (g pluginDependencyGraph) sort() ([]string, error) {
	var empty []string
	sorted := make([]string, 0, len(g))

	for p, n := range g {
		if n.incomingCount == 0 {
			empty = append(empty, p)
		}
	}

	for len(empty) > 0 {
		if g[empty[0]].exists {
			sorted = append(sorted, empty[0])

			for after := range g[empty[0]].outgoing {
				g[after].incomingCount--

				if g[after].incomingCount == 0 {
					empty = append(empty, after)
				}
			}
		}

		delete(g, empty[0])
		empty = empty[1:]
	}

	if len(g) > 0 {
		// if a cycle exists, find a cycle and report it.
		return nil, g.findDependencyCycle()
	}

	return sorted, nil
}

func (g pluginDependencyGraph) ensureNode(name string) {
	if g[name] == nil {
		g[name] = &node{
			outgoing: map[string]struct{}{},
		}
	}
}

// addNode marks a plugin as actually existing and not just something referenced
// by another plugin.
func (g pluginDependencyGraph) addNode(name string) {
	g.ensureNode(name)
	g[name].exists = true
}

// before marks that a should come before b.
func (g pluginDependencyGraph) before(a, b string) {
	g.after(b, a)
}

// after marks that a should come after b.
func (g pluginDependencyGraph) after(a, b string) {
	g.ensureNode(a)
	g.ensureNode(b)
	if _, exists := g[b].outgoing[a]; !exists {
		g[b].outgoing[a] = struct{}{}
		g[a].incomingCount++
	}
}

// sortedNodes sorts plugins by name in ascending order.
func (g pluginDependencyGraph) sortedNodes() []string {
	var nodes []string

	for n := range g {
		nodes = append(nodes, n)
	}

	sort.Strings(nodes)
	return nodes
}

// sortedNodes sorts after dependencies for plugin n in ascending order.
func (g pluginDependencyGraph) sortedOutgoing(n string) []string {
	var outgoing []string

	for o := range g[n].outgoing {
		outgoing = append(outgoing, o)
	}

	sort.Strings(outgoing)
	return outgoing
}

// findDependencyCycle finds a cycle in the DAG and reports it back as a
// dependencyCycleError.
func (g pluginDependencyGraph) findDependencyCycle() error {
	var findCycle func(node string, path []string, visited map[string]bool) []string
	findCycle = func(node string, path []string, visited map[string]bool) []string {
		if visited[node] {
			return path
		}

		visited[node] = true
		for _, after := range g.sortedOutgoing(node) {
			path = append(path, after)
			if cycle := findCycle(after, path, visited); cycle != nil {
				return cycle
			}
			path = path[:len(path)-1]
		}
		visited[node] = false

		return nil
	}

	var cycle []string

	for _, n := range g.sortedNodes() {
		cycle = findCycle(n, []string{n}, map[string]bool{})
		if cycle != nil {
			break
		}
	}

	return &dependencyCycleError{
		cycle: cycle,
	}
}

type dependencyCycleError struct {
	cycle []string
}

func (err *dependencyCycleError) Error() string {
	var b strings.Builder
	b.WriteString("dependency cycle: ")

	for i, p := range err.cycle {
		b.WriteString(p)
		if i != len(err.cycle)-1 {
			b.WriteString("->")
		}
	}

	return b.String()
}
