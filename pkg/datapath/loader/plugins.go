// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/bpf/analyze"
	"github.com/cilium/cilium/pkg/datapath/config"
	plugin "github.com/cilium/cilium/pkg/datapath/plugins/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"

	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
)

const (
	bpfLoaderGCRetryInterval = time.Minute
)

func linkToInterfaceInfo(l netlink.Link) *datapathplugins.AttachmentContext_InterfaceInfo {
	return &datapathplugins.AttachmentContext_InterfaceInfo{
		Name: l.Attrs().Name,
	}
}

func attachmentContextHost(ep endpoint.Endpoint, device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Host_{
			Host: &datapathplugins.AttachmentContext_Host{
				Iface: linkToInterfaceInfo(device),
			},
		},
	}
}

func attachmentContextLXC(ep endpoint.Endpoint) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Lxc{
			Lxc: &datapathplugins.AttachmentContext_LXC{
				Iface: &datapathplugins.AttachmentContext_InterfaceInfo{
					Name: ep.InterfaceName(),
				},
				PodInfo: &datapathplugins.AttachmentContext_PodInfo{
					Namespace: ep.GetK8sNamespace(),
					Name:      ep.GetK8sPodName(),
				},
			},
		},
	}
}

func attachmentContextOverlay(device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Overlay_{
			Overlay: &datapathplugins.AttachmentContext_Overlay{
				Iface: linkToInterfaceInfo(device),
			},
		},
	}
}

// bpfCollectionLoader coordinates between datapath plugins when loading a BPF
// collection. It provides an interface similar to the usual bpf.Load and
// bpf.LoadAndAssign functions.
type bpfCollectionLoader struct {
	pluginOperationsDir string
	pluginsEnabled      bool
	gcWakeup            chan struct{}
	// gcMu prevents the GC loop from running while Load/LoadAndAssign is
	// running, since we don't want to accidentally delete the staging
	// directories for ongoing operations. The GC loop takes a write lock
	// and releases it after staging directory GC completes.
	// Load/LoadAndAssign take a read lock which is released by the cleanup
	// function they return.
	gcMu lock.RWMutex
}

func newBPFCollectionLoader(pluginsEnabled bool, pluginOperationsDir string) *bpfCollectionLoader {
	return &bpfCollectionLoader{
		pluginOperationsDir: pluginOperationsDir,
		pluginsEnabled:      pluginsEnabled,
		gcWakeup:            make(chan struct{}, 1),
	}
}

func (l *bpfCollectionLoader) runGC(logger *slog.Logger, jg job.Group) {
	if !l.pluginsEnabled {
		return
	}

	logger = logger.WithGroup("plugins-staging-gc")

	jg.Add(job.OneShot("plugins-staging-gc", func(ctx context.Context, health cell.Health) error {
		var retry <-chan time.Time

		for {
			select {
			case <-l.gcWakeup:
			case <-retry:
			}

			retry = nil

			logger.Info("Begin BPF collection loader GC pass")
			l.gcMu.Lock()
			if err := bpf.Remove(l.pluginOperationsDir); err != nil {
				logger.Warn("Unable to finish GC pass", logfields.Error, err)
				health.Degraded("Unable to finish GC pass", err)
				retry = time.After(bpfLoaderGCRetryInterval)
			} else {
				logger.Info("Finished BPF collection loader GC pass")
				health.OK("Finished BPF collection loader GC pass")
			}
			l.gcMu.Unlock()
		}
	}))

	// Run gc at least once on startup
	l.gc()
}

// gc is triggered if cleanup of the operation directory fails after a load
// sequence. It ensures that operation directories from failed or partially
// completed operations are eventually cleaned up.
func (l *bpfCollectionLoader) gc() {
	select {
	case l.gcWakeup <- struct{}{}:
	default:
	}
}

// LoadAndAssign loads spec into the kernel and assigns the requested eBPF
// objects to the given object. When datapath plugins are enabled, it
// coordinates with plugins and instruments the collection accordingly. When
// datapath plugins are disabled, it acts exactly like bpf.LoadAndAssign.
//
// If successful, LoadAndAssign returns two functions, commit and cleanup.
// Similar to the commit function returned by bpf.LoadCollection, commit commits
// pending map pins to the bpf file system for maps that that were found to be
// incompatible with their pinned counterparts, or for maps with certain flags
// that modify the default pinning behaviour. It also replaces any
// plugin-provided pins or pinned plugin hook program links for this attachment
// context with those created by this load operation. cleanup cleans up up
// transient state related to the operation such as program pins or map pins.
// cleanup must be invoked after commit regardless of whether or not commit
// returns an error.
func (l *bpfCollectionLoader) LoadAndAssign(ctx context.Context, logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *config.Config, attachmentContext *datapathplugins.AttachmentContext, pinsDir string) (func() error, func(), error) {
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

// Load loads the given spec into the kernel with the specified opts. When
// datapath plugins are enabled, it coordinates with plugins and instruments
// the collection accordingly. When datapath plugins are disabled, it acts
// exactly like bpf.LoadCollection.
//
// If successful, Load returns two functions, commit and cleanup. Similar to the
// commit function returned by bpf.LoadCollection, commit commits pending map
// pins to the bpf file system for maps that that were found to be incompatible
// with their pinned counterparts, or for maps with certain flags that modify
// the default pinning behaviour. It also replaces any plugin-provided pins or
// pinned plugin hook program links for this attachment context with those
// created by this load operation. cleanup cleans up up transient state related
// to the operation such as program pins or map pins. cleanup must be invoked
// after commit regardless of whether or not commit returns an error.
func (l *bpfCollectionLoader) Load(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *config.Config, attachmentContext *datapathplugins.AttachmentContext, pinsDir string) (coll *ebpf.Collection, commit func() error, cleanup func(), err error) {
	if !l.pluginsEnabled {
		// If plugins were previously enabled, clean up any lingering
		// pinned links in the plugin link directories.
		if err := bpf.Remove(pinsDir); err != nil {
			logger.Warn("Failed to purge pins dir",
				logfields.Error, err,
				logfields.Path, pinsDir,
			)
		}

		coll, commit, err = bpf.LoadCollection(logger, spec, opts)
		return coll, commit, func() {}, err
	}

	instrumentCollectionRequests, err := l.prepareCollection(ctx, logger, spec, opts, lnc, attachmentContext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("preparing hooks: %w", err)
	}

	coll, commit, err = bpf.LoadCollection(logger, spec, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading collection: %w", err)
	}

	commit, cleanup, err = l.instrumentCollection(ctx, logger, coll, commit, instrumentCollectionRequests, lnc, attachmentContext, l.pluginOperationsDir, pinsDir)
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("loading hooks: %w", err)
	}

	return coll, commit, cleanup, nil
}

// prepareCollection sends a round of PrepareCollection requests to all
// registered plugins and prepares a set of InstrumentCollection requests for
// the instrumentation/load phase.
func (l *bpfCollectionLoader) prepareCollection(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *config.Config, attachmentContext *datapathplugins.AttachmentContext) (_ map[string]*datapathplugins.InstrumentCollectionRequest, err error) {
	req := &datapathplugins.PrepareCollectionRequest{
		AttachmentContext: attachmentContext,
		Collection: &datapathplugins.PrepareCollectionRequest_CollectionSpec{
			Programs: make(map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec),
			Maps:     make(map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec),
		},
	}

	for name, p := range spec.Programs {
		req.Collection.Programs[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec{
			Type:        uint32(p.Type),
			AttachType:  uint32(p.AttachType),
			SectionName: p.SectionName,
			License:     p.License,
		}
	}
	for name, m := range spec.Maps {
		req.Collection.Maps[name] = &datapathplugins.PrepareCollectionRequest_CollectionSpec_MapSpec{
			Type:       uint32(m.Type),
			KeySize:    m.KeySize,
			ValueSize:  m.ValueSize,
			MaxEntries: m.MaxEntries,
			Flags:      m.Flags,
			PinType:    uint32(m.Pinning),
		}
	}

	type prepareResult struct {
		plugin plugin.Plugin
		err    error
		resp   *datapathplugins.PrepareCollectionResponse
	}

	prepareResults := make(chan prepareResult)
	for _, p := range lnc.Plugins {
		go func(p plugin.Plugin) {
			resp, err := p.PrepareCollection(ctx, req)
			prepareResults <- prepareResult{plugin: p, err: err, resp: resp}
		}(p)
	}

	responses := make(map[string]*datapathplugins.PrepareCollectionResponse)
	hooksSpec := newHooksSpec()

	for range len(lnc.Plugins) {
		r := <-prepareResults

		logger.Debug("PrepareCollection()",
			logfields.CiliumDatapathPluginName, r.plugin.Name(),
			logfields.Request, req,
			logfields.Response, r.resp,
			logfields.Error, r.err,
		)

		if r.err != nil {
			if r.plugin.AttachmentPolicy() == api_v2alpha1.AttachmentPolicyAlways {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): %w", r.plugin.Name(), r.err))
			} else {
				logger.Info("Datapath plugin preparation failed, ignoring due to best effort attachment policy. See plugin logs for more details.",
					logfields.CiliumDatapathPluginName, r.plugin.Name(),
					logfields.Error, r.err,
				)
			}

			continue
		} else {
			responses[r.plugin.Name()] = r.resp
		}

	process_hooks:
		for _, h := range r.resp.Hooks {
			ps := spec.Programs[h.Target]
			if ps == nil {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): target program \"%s\" does not exist in the collection spec", r.plugin.Name(), h.Target))

				continue
			} else if canErr := canInstrument(ps, attachmentContext); canErr != nil {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): \"%s\": %w", r.plugin.Name(), h.Target, canErr))

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
					continue
				}

				switch c.Order {
				case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE:
					hooksSpec.hook(ps.Name, h.Type).before(r.plugin.Name(), otherPlugin.Name())
				case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_AFTER:
					hooksSpec.hook(ps.Name, h.Type).after(r.plugin.Name(), otherPlugin.Name())
				default:
					err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): invalid ordering constraint: %v", r.plugin.Name(), c.Order))
					continue process_hooks
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	instrumentCollectionRequests, programPatches, err := hooksSpec.instrumentCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("instrumenting collection: %w", err)
	}
	opts.ProgramPatches = programPatches

	for plugin, req := range instrumentCollectionRequests {
		prepareHooksResp := responses[plugin]
		req.Cookie = prepareHooksResp.Cookie
		req.Collection = &datapathplugins.InstrumentCollectionRequest_Collection{
			Programs: make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program),
			Maps:     make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map),
		}
		req.AttachmentContext = attachmentContext
	}

	return instrumentCollectionRequests, nil
}

// canInstrument makes sure that a hook can be added to the requested program.
func canInstrument(prog *ebpf.ProgramSpec, attachmentContext *datapathplugins.AttachmentContext) error {
	if bpf.IsTailCall(prog) ||
		(attachmentContext.GetLxc() != nil &&
			(prog.Name == "cil_lxc_policy" || prog.Name == "cil_lxc_policy_egress")) ||
		(attachmentContext.GetHost() != nil &&
			(prog.Name == "cil_host_policy")) {
		// It is currently not possible to do freplace for programs that are
		// inside a PROG_ARRAY map, so we have to limit instrumentation to
		// __section_entry programs.
		//
		// https://lore.kernel.org/all/20241015150207.70264-2-leon.hwang@linux.dev/
		return fmt.Errorf("cannot instrument tail call programs")
	}

	return nil
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

// instrumentCollection sends out the provided set of InstrumentCollection requests
// and, after hearing back from each plugin, attaches loaded hook programs
// to hook points inside each dispatcher.
func (l *bpfCollectionLoader) instrumentCollection(ctx context.Context, logger *slog.Logger, coll *ebpf.Collection, commit func() error, instrumentCollectionRequests map[string]*datapathplugins.InstrumentCollectionRequest, lnc *config.Config, attachmentContext *datapathplugins.AttachmentContext, opsDir string, pinsDir string) (_ func() error, _ func(), err error) {
	// Make sure the GC loop can't run, since we don't want it to delete our
	// staging directories. Released on error conditions in
	// cleanupStagingDirs(); if this function returns success, the callers
	// *MUST* call cleanup function to unlock.
	l.gcMu.RLock()

	type loadResult struct {
		plugin plugin.Plugin
		err    error
		resp   *datapathplugins.InstrumentCollectionResponse
	}

	loadResults := make(chan loadResult)
	stagingDirs := make(map[string]string)
	// Staging directories are ephemeral and should be cleaned up if this
	// operation or a subsequent attachment attempt fails. This function
	// also unlocks the gcMu, so it *MUST* be called exactly once for this
	// endpoint "soon" after this function returns.
	cleanupStagingDirs := func() {
		var needGC bool
		for plugin, dir := range stagingDirs {
			if err := bpf.Remove(dir); err != nil {
				logger.Error("Failed to clean up InstrumentCollection() staging directory",
					logfields.Error, err,
					logfields.CiliumDatapathPluginName, plugin,
					logfields.Path, dir,
				)
				needGC = true
			}
		}

		// We're done with our staging directories, so allow the GC loop
		// to run if necessary.
		l.gcMu.RUnlock()

		if needGC {
			// This probably means that something weird happened
			// and a plugin kept trying to write to the staging
			// directory after the request hung up on our end.
			// GC will keep trying until the staging dir is cleaned
			// up.
			l.gc()
		}
	}

	defer func() {
		if err != nil {
			cleanupStagingDirs()
		}
	}()

	// Set up staging directories then finalize and send InstrumentCollection
	// requests.
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
		r := <-loadResults

		req := instrumentCollectionRequests[r.plugin.Name()]
		delete(instrumentCollectionRequests, r.plugin.Name())

		logger.Debug("InstrumentCollection()",
			logfields.CiliumDatapathPluginName, r.plugin.Name(),
			logfields.Request, req,
			logfields.Response, r.resp,
			logfields.Error, r.err,
		)

		if r.err != nil {
			err = errors.Join(err, fmt.Errorf("%s: InstrumentCollection(): %w", r.plugin.Name(), r.err))

			continue
		}

		// Replace the pinned program at each pin path with a pinned
		// freplace link.
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
		// clear out old pinned freplace links or plugin-provided pins.
		if err := bpf.Remove(pinsDir); err != nil {
			return fmt.Errorf("purging plugin pins dir %s: %w", pinsDir, err)
		}

		if err := bpf.MkdirBPF(pinsDir); err != nil {
			return fmt.Errorf("ensuring the existence of plugin pins dir %s: %w", pinsDir, err)
		}

		for plugin, pluginStagingDir := range stagingDirs {
			pluginPinsDir := filepath.Join(pinsDir, plugin)

			if err := bpf.MkdirBPF(pluginPinsDir); err != nil {
				return fmt.Errorf("ensuring the existence of plugin pins dir %s: %w", pluginPinsDir, err)
			}

			// move pins from the staging directory to the pins
			// directory for this plugin and attachment context.
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
