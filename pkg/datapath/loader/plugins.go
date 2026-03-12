package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/bpf/analyze"
	plugin "github.com/cilium/cilium/pkg/datapath/plugins/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
)

const (
	bpfLoaderGCRetryInterval = time.Minute
)

type bpfCollectionLoader struct {
	pluginOperationsDir string
	pluginsEnabled      bool
	logger              *slog.Logger
	gcOnce              sync.Once
	gcWakeup            chan struct{}
	gcMu                sync.RWMutex
}

func (l *bpfCollectionLoader) gc() {
	l.logger.Info("Start BPF collection loader GC loop")
	defer l.logger.Info("Stop BPF collection loader GC loop")

	if l.gcWakeup == nil {
		l.gcWakeup = make(chan struct{}, 1)
	}

	go l.gcOnce.Do(func() {
		var retry <-chan time.Time

		for {
			select {
			case <-l.gcWakeup:
			case <-retry:
			}

			retry = nil

			l.logger.Info("Begin BPF collection loader GC pass")
			l.gcMu.Lock()
			if err := bpf.Remove(bpffsPluginsOperationsDir(bpf.CiliumPath())); err != nil {
				l.logger.Warn("Unable to finish GC pass", logfields.Error, err)
				retry = time.After(bpfLoaderGCRetryInterval)
			} else {
				l.logger.Info("Finished BPF collection loader GC pass")
			}
			l.gcMu.Unlock()
		}
	})

	select {
	case l.gcWakeup <- struct{}{}:
	default:
	}
}

func (l *bpfCollectionLoader) LoadAndAssign(ctx context.Context, logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, pinsDir string) (func() error, func(), error) {
	keep, err := analyze.Fields(to)
	if err != nil {
		return nil, nil, fmt.Errorf("analyzing fields of %T: %w", to, err)
	}
	opts.Keep = keep

	coll, commit, cleanupLinks, err := l.Load(ctx, logger, spec, opts, lnc, attachmentContext, pinsDir)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}

	if err := coll.Assign(to); err != nil {
		cleanupLinks()
		coll.Close()
		return nil, nil, fmt.Errorf("assigning eBPF objects to %T: %w", to, err)
	}

	return commit, cleanupLinks, nil
}

func (l *bpfCollectionLoader) Load(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, pinsDir string) (coll *ebpf.Collection, commit func() error, cleanup func(), err error) {
	if !l.pluginsEnabled {
		fmt.Printf("JORDAN\n")
		// If plugins were previously enabled, clean up any lingering
		// pinned links in the plugin link directories.
		if err := bpf.Remove(pinsDir); err != nil {
			logger.Error("Failed to purge pins dir",
				logfields.Error, err,
				logfields.Path, pinsDir,
			)
		}

		coll, commit, err = bpf.LoadCollection(logger, spec, opts)
		return coll, commit, func() {}, err
	}
	fmt.Printf("JORDAN RIFE %v\n", lnc.Plugins)

	instrumentCollectionRequests, err := l.prepareCollection(ctx, logger, spec, lnc, attachmentContext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("preparing hooks: %w", err)
	}

	coll, commit, err = bpf.LoadCollection(logger, spec, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading collection: %w", err)
	}
	defer func() {
		if err != nil {
			coll.Close()
		}
	}()

	commit, cleanup, err = l.instrumentCollection(ctx, logger, coll, commit, instrumentCollectionRequests, lnc, attachmentContext, l.pluginOperationsDir, pinsDir)
	if err != nil {
		return coll, commit, nil, fmt.Errorf("loading hooks: %w", err)
	}

	return coll, commit, cleanup, nil
}

func (l *bpfCollectionLoader) prepareCollection(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext) (_ map[string]*datapathplugins.InstrumentCollectionRequest, err error) {
	req := &datapathplugins.PrepareCollectionRequest{
		AttachmentContext: attachmentContext,
		LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
		Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
			Programs: make(map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec),
			Maps:     make(map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec),
		},
	}

	for name := range spec.Programs {
		req.Collection.Programs[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{}
	}
	for name := range spec.Maps {
		req.Collection.Maps[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{}
	}

	type prepareResult struct {
		plugin plugin.Plugin
		err    error
		resp   *datapathplugins.PrepareCollectionResponse
	}

	remaining := len(lnc.Plugins)
	prepareResults := make(chan prepareResult)
	for _, p := range lnc.Plugins {
		go func(p plugin.Plugin) {
			resp, err := p.PrepareCollection(ctx, req)
			prepareResults <- prepareResult{plugin: p, err: err, resp: resp}
		}(p)
	}

	responses := make(map[string]*datapathplugins.PrepareCollectionResponse)
	hooksSpec := newHooksSpec()

	for remaining > 0 {
		var r prepareResult
		select {
		case r = <-prepareResults:
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for PrepareCollection() responses: %w", ctx.Err())
		}

		remaining--

		if r.err != nil {
			logger.Error("PrepareCollection() failed",
				logfields.Error, r.err,
				"plugin", r.plugin.Name(),
			)

			if r.plugin.AttachmentPolicy() == api_v2alpha1.AttachmentPolicyAlways {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): %w", r.plugin.Name(), r.err))
			}

			continue
		} else {
			responses[r.plugin.Name()] = r.resp
		}

		logger.Debug("PrepareCollection() succeeded", "plugin", r.plugin.Name())
	process_hooks:
		for _, h := range r.resp.Hooks {
			ps := spec.Programs[h.Target]
			if ps == nil {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): target program \"%s\" does not exist in the collection spec", r.plugin.Name(), h.Target))

				continue
			}

			if h.Type != datapathplugins.HookType_PRE && h.Type != datapathplugins.HookType_POST {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): invalid hook type %v", r.plugin.Name(), h.Type))

				continue
			}

			hooksSpec.hook(ps.Name, h.Type).addNode(r.plugin.Name())

			for _, c := range h.Constraints {
				otherPlugin := lnc.Plugins[c.Plugin]
				if otherPlugin == nil {
					logger.Debug("PrepareCollection() constraint references unknown plugin",
						"plugin", r.plugin.Name(),
						"otherPlugin", c.Plugin,
					)

					continue
				}

				switch c.Order {
				case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE:
					hooksSpec.hook(ps.Name, h.Type).before(r.plugin.Name(), otherPlugin.Name())
				case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_AFTER:
					hooksSpec.hook(ps.Name, h.Type).after(r.plugin.Name(), otherPlugin.Name())
				default:
					err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): invalid ordering constraint: %v", r.plugin.Name(), h.Type))
					continue process_hooks
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	instrumentCollectionRequests, err := hooksSpec.instrumentCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("instrumenting collection: %w", err)
	}

	for plugin, req := range instrumentCollectionRequests {
		prepareHooksResp := responses[plugin]
		req.Cookie = prepareHooksResp.Cookie
		req.Collection = &datapathplugins.InstrumentCollectionRequest_Collection{
			Programs: make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program),
			Maps:     make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map),
		}
		req.AttachmentContext = attachmentContext
		req.LocalNodeConfig = &datapathplugins.LocalNodeConfig{} // TODO
	}

	return instrumentCollectionRequests, nil
}

func progID(p *ebpf.Program) (uint32, error) {
	info, err := p.Info()
	if err != nil {
		return 0, err
	}

	id, avail := info.ID()
	if !avail {
		return 0, err
	}

	return uint32(id), nil
}

func mapID(m *ebpf.Map) (uint32, error) {
	info, err := m.Info()
	if err != nil {
		return 0, err
	}

	id, avail := info.ID()
	if !avail {
		return 0, err
	}

	return uint32(id), nil
}

func (l *bpfCollectionLoader) instrumentCollection(ctx context.Context, logger *slog.Logger, coll *ebpf.Collection, commit func() error, instrumentCollectionRequests map[string]*datapathplugins.InstrumentCollectionRequest, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, opsDir string, pinsDir string) (_ func() error, _ func(), err error) {
	l.gcMu.RLock()
	defer l.gcMu.RUnlock()

	type loadResult struct {
		plugin plugin.Plugin
		err    error
		resp   *datapathplugins.InstrumentCollectionResponse
	}

	loadResults := make(chan loadResult)
	stagingDirs := make(map[string]string)
	cleanupStagingDirs := func() {
		var needGC bool
		for plugin, dir := range stagingDirs {
			if err := bpf.Remove(dir); err != nil {
				logger.Error("Failed to clean up InstrumentCollection() staging directory",
					logfields.Error, err,
					"plugin", plugin,
					logfields.Path, dir,
				)
				needGC = true
			}
		}
		if needGC {
			l.gc()
		}
	}

	defer func() {
		if err != nil {
			cleanupStagingDirs()
		}
	}()

	for plugin, req := range instrumentCollectionRequests {
		requestID := uuid.New().String()
		stagingDirs[plugin] = bpffsPluginOperationDir(opsDir, plugin, requestID)
		hookPinsDir := filepath.Join(stagingDirs[plugin], "hooks")
		req.Pins = filepath.Join(stagingDirs[plugin], "pins")

		if err := bpf.MkdirBPF(hookPinsDir); err != nil {
			return nil, nil, fmt.Errorf("creating BPF operation hooks directory: %w", err)
		}

		if err := bpf.MkdirBPF(req.Pins); err != nil {
			return nil, nil, fmt.Errorf("creating BPF operation pins directory: %w", err)
		}

		for name, p := range coll.Programs {
			id, err := progID(p)
			if err != nil {
				return nil, nil, fmt.Errorf("getting ID for program %s: %w", name, err)
			}

			req.Collection.Programs[name] = &datapathplugins.InstrumentCollectionRequest_Collection_Program{
				Id: id,
			}
		}
		for name, m := range coll.Maps {
			id, err := mapID(m)
			if err != nil {
				return nil, nil, fmt.Errorf("getting ID for map %s: %w", name, err)
			}
			req.Collection.Maps[name] = &datapathplugins.InstrumentCollectionRequest_Collection_Map{
				Id: id,
			}
		}

		for _, hook := range req.Hooks {
			prog := coll.Programs[hook.Target]
			if prog == nil {
				return nil, nil, fmt.Errorf("InstrumentCollectionRequest for %s references a non-existent program: %s", plugin, hook.Target)
			}

			id, err := progID(prog)
			if err != nil {
				return nil, nil, fmt.Errorf("getting ID for target program %s: %w", hook.Target, err)
			}

			hook.AttachTarget.ProgramId = id
			hook.PinPath = filepath.Join(hookPinsDir, fmt.Sprintf("%s_%s", hook.Target, hook.AttachTarget.SubprogName))
		}

		go func(req *datapathplugins.InstrumentCollectionRequest) {
			p := lnc.Plugins[plugin]
			resp, err := p.InstrumentCollection(ctx, req)
			loadResults <- loadResult{plugin: p, err: err, resp: resp}
		}(req)
	}

	for len(instrumentCollectionRequests) > 0 {
		var r loadResult
		select {
		case r = <-loadResults:
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("waiting for InstrumentCollection() responses: %w", ctx.Err())
		}

		req := instrumentCollectionRequests[r.plugin.Name()]
		delete(instrumentCollectionRequests, r.plugin.Name())

		if r.err != nil {
			logger.Error("InstrumentCollection() failed",
				logfields.Error, r.err,
				"plugin", r.plugin.Name(),
			)

			err = errors.Join(err, fmt.Errorf("%s: InstrumentCollection(): %w", r.plugin.Name(), r.err))

			continue
		}

		logger.Debug("InstrumentCollection() succeeded", "plugin", r.plugin.Name())

		for _, hook := range req.Hooks {
			prog, err := ebpf.LoadPinnedProgram(hook.PinPath, &ebpf.LoadPinOptions{})
			if err != nil {
				return nil, nil, fmt.Errorf("load pinned hook program at %s: %w", hook.PinPath, err)
			}
			if err := os.Remove(hook.PinPath); err != nil {
				return nil, nil, fmt.Errorf("removing pinned hook program at %s: %w", hook.PinPath, err)
			}
			freplace, err := link.AttachFreplace(coll.Programs[hook.Target], hook.AttachTarget.SubprogName, prog)
			if err != nil {
				return nil, nil, fmt.Errorf("creating freplace link for hook: %w", err)
			}
			defer freplace.Close()
			if err := freplace.Pin(hook.PinPath); err != nil {
				return nil, nil, fmt.Errorf("pinning freplace link for hook to %s: %w", hook.PinPath, err)
			}
		}
	}

	if err != nil {
		return nil, nil, err
	}

	return func() error {
		defer cleanupStagingDirs()

		if err := bpf.Remove(pinsDir); err != nil {
			err = errors.Join(err, fmt.Errorf("purging plugin pins dir %s: %w", pinsDir, err))
		}

		if err := bpf.MkdirBPF(pinsDir); err != nil {
			return fmt.Errorf("ensuring the existence of plugin pins dir %s: %w", pinsDir, err)
		}

		for plugin, pluginStagingDir := range stagingDirs {
			pluginPinsDir := filepath.Join(pinsDir, plugin)

			if err := bpf.MkdirBPF(pluginPinsDir); err != nil {
				return fmt.Errorf("ensuring the existence of plugin pins dir %s: %w", pluginPinsDir, err)
			}

			for _, subDir := range []string{
				"hooks",
				"pins",
			} {
				oldPath := filepath.Join(pluginStagingDir, subDir)
				newPath := filepath.Join(pluginPinsDir, subDir)

				if err := os.Rename(oldPath, newPath); err != nil {
					return fmt.Errorf("committing pins for plugin %s (%s -> %s): %w", plugin, oldPath, newPath, err)
				}
			}
		}

		return commit()
	}, cleanupStagingDirs, nil
}

func (l *loader) initializePluginsDir() error {
	return bpf.Remove(bpffsPluginsOperationsDir(bpf.CiliumPath()))
}

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

func (hs *hooksSpec) instrumentCollection(cs *ebpf.CollectionSpec) (map[string]*datapathplugins.InstrumentCollectionRequest, error) {
	var err error
	hooks := make(map[string]*datapathplugins.InstrumentCollectionRequest)

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

		if err := hs.instrumentProgram(cs.Programs[hookTarget], pre, post, hooks); err != nil {
			err = errors.Join(err, fmt.Errorf("instrumenting %s: %w", hookTarget, err))
			continue
		}
	}

	return hooks, err
}

func (hs *hooksSpec) instrumentProgram(ps *ebpf.ProgramSpec, pre []string, post []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest) error {
	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return fmt.Errorf("unable to extract function BTF info for target program")
	}

	var dispatcherInstructions []asm.Instruction

	// Preserve ctx in R6, callee saved register.
	dispatcherInstructions = append(dispatcherInstructions, asm.Mov.Reg(asm.R6, asm.R1))

	for _, plugin := range pre {
		subprogName := preHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
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

	dispatcherInstructions = append(dispatcherInstructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Call.Label(btfMeta.Name),
		asm.Mov.Reg(asm.R7, asm.R0),
	)

	for _, plugin := range post {
		subprogName := postHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
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

	dispatcherInstructions = append(dispatcherInstructions,
		asm.Mov.Reg(asm.R0, asm.R7),
		asm.Return().WithSymbol("return"),
	)

	entryName := fmt.Sprintf("__%s__", btfMeta.Name)
	dispatcherInstructions[0] = btf.WithFuncMetadata(
		dispatcherInstructions[0].
			WithSymbol(entryName).
			WithSource(asm.Comment(entryName)),
		&btf.Func{
			Name:    entryName,
			Type:    funcProto,
			Linkage: btf.GlobalFunc,
		})
	dispatcherInstructions = append(dispatcherInstructions, ps.Instructions...)

	postHookProto := *funcProto
	postHookProto.Params = append(
		append([]btf.FuncParam(nil), postHookProto.Params...),
		btf.FuncParam{Name: "ret", Type: funcProto.Return},
	)

	for _, plugin := range pre {
		hookName := preHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
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
		dispatcherInstructions = append(dispatcherInstructions,
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

	ps.Instructions = dispatcherInstructions

	return nil
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
