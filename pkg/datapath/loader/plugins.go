package loader

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func preHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__pre_hook_%s__", pluginName)
}

func postHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__post_hook_%s__", pluginName)
}

type hooksSpec struct {
	hooks map[string]map[datapathplugins.HookType]*pluginDependencyGraph
}

func newHooksSpec() *hooksSpec {
	return &hooksSpec{
		hooks: make(map[string]map[datapathplugins.HookType]*pluginDependencyGraph),
	}
}

func (hs *hooksSpec) hook(target string, hookType datapathplugins.HookType) *pluginDependencyGraph {
	if hs.hooks[target] == nil {
		hs.hooks[target] = map[datapathplugins.HookType]*pluginDependencyGraph{
			datapathplugins.HookType_PRE:  &pluginDependencyGraph{},
			datapathplugins.HookType_POST: &pluginDependencyGraph{},
		}
	}

	return hs.hooks[target][hookType]
}

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

		patch, err := hs.instrumentProgram(cs.Programs[hookTarget], pre, post, hooks)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("instrumenting %s: %w", hookTarget, err))
			continue
		}
		programPatches[hookTarget] = patch
	}

	return hooks, programPatches, err
}

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
		subprogName := preHookSubprogName(plugin)
		prologue = append(prologue,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Call.Label(subprogName),
			asm.JNE.Imm32(asm.R0, -1, "return"),
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

	prologue = append(prologue,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Call.Label(btfMeta.Name),
		asm.Mov.Reg(asm.R7, asm.R0),
	)

	for _, plugin := range post {
		subprogName := postHookSubprogName(plugin)
		prologue = append(prologue,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R7),
			asm.Call.Label(subprogName),
			asm.JNE.Imm32(asm.R0, -1, "return"),
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

	prologue = append(prologue,
		asm.Mov.Reg(asm.R0, asm.R7),
		asm.Return().WithSymbol("return"),
	)

	entryName := fmt.Sprintf("__%s__", btfMeta.Name)
	prologue[0] = btf.WithFuncMetadata(
		prologue[0].
			WithSymbol(entryName).
			WithSource(asm.Comment(entryName)),
		&btf.Func{
			Name:    entryName,
			Type:    funcProto,
			Linkage: btf.GlobalFunc,
		})

	var epilogue asm.Instructions

	postHookProto := *funcProto
	postHookProto.Params = append(
		append([]btf.FuncParam(nil), postHookProto.Params...),
		btf.FuncParam{Name: "ret", Type: funcProto.Return},
	)

	for _, plugin := range pre {
		hookName := preHookSubprogName(plugin)
		epilogue = append(epilogue,
			btf.WithFuncMetadata(
				asm.Mov.Imm(asm.R0, 0).
					WithSymbol(hookName).
					WithSource(asm.Comment(hookName)),
				&btf.Func{
					Name: hookName,
					Type: funcProto,
					// BTF_FUNC_GLOBAL ensures programs are independently verified.
					Linkage: btf.GlobalFunc,
				}),
			asm.Return(),
		)
	}
	for _, plugin := range post {
		hookName := postHookSubprogName(plugin)
		epilogue = append(epilogue,
			btf.WithFuncMetadata(
				asm.Mov.Imm(asm.R0, 0).
					WithSymbol(hookName).
					WithSource(asm.Comment(hookName)),
				&btf.Func{
					Name: hookName,
					Type: &postHookProto,
					// BTF_FUNC_GLOBAL ensures programs are independently verified.
					Linkage: btf.GlobalFunc,
				}),
			asm.Return(),
		)
	}

	return func(insns asm.Instructions) (asm.Instructions, error) {
		return append(prologue, append(insns, epilogue...)...), nil
	}, nil
}

type node struct {
	exists        bool
	outgoing      map[string]struct{}
	incomingCount int
}

type pluginDependencyGraph map[string]*node

func (g pluginDependencyGraph) sort() ([]string, error) {
	var empty []string
	sorted := make([]string, 0, len(g))

	for p, n := range g {
		if n.incomingCount == 0 {
			empty = append(empty, p)
		}
	}

	for len(empty) > 0 {
		batchSize := len(empty)

		for i := 0; i < batchSize; i++ {
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
	}

	if len(g) > 0 {
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

func (g pluginDependencyGraph) addNode(name string) {
	g.ensureNode(name)
	g[name].exists = true
}

func (g pluginDependencyGraph) before(a, b string) {
	g.after(b, a)
}

func (g pluginDependencyGraph) after(a, b string) {
	g.ensureNode(a)
	g.ensureNode(b)
	if _, exists := g[b].outgoing[a]; !exists {
		g[b].outgoing[a] = struct{}{}
		g[a].incomingCount++
	}
}

func (g pluginDependencyGraph) sortedNodes() []string {
	var nodes []string

	for n := range g {
		nodes = append(nodes, n)
	}

	sort.Strings(nodes)
	return nodes
}

func (g pluginDependencyGraph) sortedOutgoing(n string) []string {
	var outgoing []string

	for o := range g[n].outgoing {
		outgoing = append(outgoing, o)
	}

	sort.Strings(outgoing)
	return outgoing
}

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
	msg := "dependency cycle: "

	for i, p := range err.cycle {
		msg += p
		if i != len(err.cycle)-1 {
			msg += "->"
		}
	}

	return msg
}
