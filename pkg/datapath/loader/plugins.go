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
	"slices"
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
	"github.com/cilium/cilium/pkg/container/set"
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
	bpfLoaderGCRetryInterval               = time.Minute
	preHookDispatcherProgPrefix            = "pre_dispatcher_"
	staticTailCallHookDispatcherProgPrefix = "tail_call_static_dispatcher_"
	exitHookDispatcherProgPrefix           = "exit_dispatcher_"
	pluginStateMapName                     = "plugin_state_map"
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

func attachmentContextWireguard(device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Wireguard_{
			Wireguard: &datapathplugins.AttachmentContext_Wireguard{
				Iface: linkToInterfaceInfo(device),
			},
		},
	}
}

func attachmentContextXDP(device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Xdp{
			Xdp: &datapathplugins.AttachmentContext_XDP{
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
	if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
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

	instrumentCollectionRequests, hookSlots, err := l.prepareCollection(ctx, logger, spec, opts, lnc, attachmentContext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("preparing hooks: %w", err)
	}

	coll, commit, err = bpf.LoadCollection(logger, spec, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading collection: %w", err)
	}

	commit, cleanup, err = l.instrumentCollection(ctx, logger, coll, commit, instrumentCollectionRequests, lnc, attachmentContext, l.pluginOperationsDir, pinsDir, hookSlots)
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("loading hooks: %w", err)
	}

	return coll, commit, cleanup, nil
}

// prepareCollection sends a round of PrepareCollection requests to all
// registered plugins and prepares a set of InstrumentCollection requests for
// the instrumentation/load phase.
func (l *bpfCollectionLoader) prepareCollection(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *config.Config, attachmentContext *datapathplugins.AttachmentContext) (_ map[string]*datapathplugins.InstrumentCollectionRequest, _ map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, err error) {
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
			} else if canErr := canInstrument(spec, ps, h.Type); canErr != nil {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): \"%s\": %w", r.plugin.Name(), h.Target, canErr))

				continue
			}

			if h.Type != datapathplugins.HookType_PRE && h.Type != datapathplugins.HookType_POST && h.Type != datapathplugins.HookType_TAIL_CALL && h.Type != datapathplugins.HookType_EXIT {
				err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): invalid hook type %v", r.plugin.Name(), h.Type))

				continue
			}

			if h.TailCallTarget != "" {
				tgt, resolveErr := resolveTailCallTarget(spec, h)
				if resolveErr != nil {
					err = errors.Join(err, fmt.Errorf("%s: PrepareCollection(): \"%s\": %w", r.plugin.Name(), h.Target, resolveErr))

					continue
				}
				hooksSpec.addTailCallTarget(ps.Name, r.plugin.Name(), tgt)
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
		return nil, nil, err
	}

	instrumentCollectionRequests, hookSlots, err := hooksSpec.instrumentCollection(spec, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("instrumenting collection: %w", err)
	}

	for plugin, req := range instrumentCollectionRequests {
		prepareHooksResp := responses[plugin]
		req.Cookie = prepareHooksResp.Cookie
		req.Collection = &datapathplugins.InstrumentCollectionRequest_Collection{
			Programs: make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Program),
			Maps:     make(map[string]*datapathplugins.InstrumentCollectionRequest_Collection_Map),
		}
		req.AttachmentContext = attachmentContext
	}

	return instrumentCollectionRequests, hookSlots, nil
}

func isPolicyProgram(name string) bool {
	return name == "cil_lxc_policy" || name == "cil_lxc_policy_egress" || name == "cil_host_policy"
}

// canInstrument makes sure that a hook can be added to the requested program.
func canInstrument(cs *ebpf.CollectionSpec, prog *ebpf.ProgramSpec, hookType datapathplugins.HookType) error {
	if hookType == datapathplugins.HookType_POST && (bpf.IsTailCall(prog) || isPolicyProgram(prog.Name)) {
		return fmt.Errorf("cannot instrument tail call programs with POST hooks; inside a PROG_ARRAY map, so we have to limit POST hook instrumentation to __section_entry programs.")
	}

	if (hookType == datapathplugins.HookType_EXIT || hookType == datapathplugins.HookType_TAIL_CALL ||
		(hookType == datapathplugins.HookType_PRE && (bpf.IsTailCall(prog) || isPolicyProgram(prog.Name)))) && bpf.CallsMapSpec(cs) == nil {
		return fmt.Errorf("cannot instrument with %s hooks: collection has no calls map to hold the dispatcher", hookType)
	}

	return nil
}

// resolveTailCallTarget resolves the tail_call_target of a TAIL_CALL hook to
// the (calls map, slot) pair that static tail calls into it use.
func resolveTailCallTarget(cs *ebpf.CollectionSpec, h *datapathplugins.PrepareCollectionResponse_HookSpec) (target, error) {
	if h.Type != datapathplugins.HookType_TAIL_CALL {
		return target{}, fmt.Errorf("tail_call_target is only supported on %s hooks, got %s", datapathplugins.HookType_TAIL_CALL, h.Type)
	}

	tp := cs.Programs[h.TailCallTarget]
	if tp == nil {
		return target{}, fmt.Errorf("tail_call_target \"%s\" does not exist in the collection spec", h.TailCallTarget)
	}

	slot, err := bpf.TailCallSlot(tp)
	if err != nil {
		return target{}, fmt.Errorf("tail_call_target \"%s\": %w", h.TailCallTarget, err)
	}

	return target{mapName: bpf.CallsMapSpec(cs).Name, slot: slot}, nil
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
func (l *bpfCollectionLoader) instrumentCollection(ctx context.Context, logger *slog.Logger, coll *ebpf.Collection, commit func() error, instrumentCollectionRequests map[string]*datapathplugins.InstrumentCollectionRequest, lnc *config.Config, attachmentContext *datapathplugins.AttachmentContext, opsDir string, pinsDir string, hookSlots map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32) (_ func() error, _ func(), err error) {
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

		for i, hook := range req.Hooks {
			hook.PinPath = filepath.Join(hookPinsDir, fmt.Sprintf("%s_%s_%d", hook.Target, hook.Type, i))

			// Tail-called hooks are inserted into a tail-call map slot rather than attached via freplace,
			// so they do not target a specific subprogram and do not require AttachTarget.ProgramId.
			if hook.GetAttachTarget().GetSubprogName() == "" {
				continue
			}

			prog := coll.Programs[hook.Target]
			if prog == nil {
				return nil, nil, fmt.Errorf("InstrumentCollectionRequest for %s references a non-existent program: %s", plugin, hook.Target)
			}

			id, err := progID(prog)
			if err != nil {
				return nil, nil, fmt.Errorf("getting ID for target program %s: %w", hook.Target, err)
			}

			hook.AttachTarget.ProgramId = id
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
		// freplace link or populate tail-call slot.
		for _, hook := range req.Hooks {
			prog, err := ebpf.LoadPinnedProgram(hook.PinPath, &ebpf.LoadPinOptions{})
			if err != nil {
				return nil, nil, fmt.Errorf("load pinned hook program at %s: %w", hook.PinPath, err)
			}
			if err := os.Remove(hook.PinPath); err != nil {
				return nil, nil, fmt.Errorf("removing pinned hook program at %s: %w", hook.PinPath, err)
			}

			if hook.GetAttachTarget().GetSubprogName() == "" {
				callsMap := bpf.CallsMap(coll)
				if callsMap == nil {
					return nil, nil, fmt.Errorf("calls map not found in collection")
				}
				if err := callsMap.Put(hookSlots[hook], prog); err != nil {
					return nil, nil, fmt.Errorf("putting tail call hook program into %s slot %d: %w", callsMap, hookSlots[hook], err)
				}
				continue
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

func staticTailCallHookSubprogName(pluginName string, origSlot uint32) string {
	return fmt.Sprintf("__tail_call_hook_%s_to_%d__", pluginName, origSlot)
}

func exitHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__exit_hook_%s__", pluginName)
}

// hooksSpec tracks inter-plugin dependencies and applies them to instrument
// programs in BPF collections with appropriate dispatchers.
type hooksSpec struct {
	hooks        map[string]map[datapathplugins.HookType]*pluginDependencyGraph
	hasExitHooks bool
	// tailCallTargets maps source program -> plugin -> resolved tail_call_target
	// filters for that plugin's TAIL_CALL hooks on the source program. A plugin
	// without an entry is unfiltered and intercepts all outbound static tail calls.
	// A plugin with an entry only intercepts tail calls into those targets, even
	// if it also sent TAIL_CALL hooks without a tail_call_target for the source.
	tailCallTargets map[string]map[string][]target
}

func newHooksSpec() *hooksSpec {
	return &hooksSpec{
		hooks:           make(map[string]map[datapathplugins.HookType]*pluginDependencyGraph),
		tailCallTargets: make(map[string]map[string][]target),
	}
}

// addTailCallTarget restricts plugin's TAIL_CALL hooks on src to tail calls
// into tgt. Multiple targets for the same (src, plugin) are OR'd.
func (hs *hooksSpec) addTailCallTarget(src, plugin string, tgt target) {
	if hs.tailCallTargets[src] == nil {
		hs.tailCallTargets[src] = make(map[string][]target)
	}
	if !slices.Contains(hs.tailCallTargets[src][plugin], tgt) {
		hs.tailCallTargets[src][plugin] = append(hs.tailCallTargets[src][plugin], tgt)
	}
}

// tailCallMatches reports whether plugin's TAIL_CALL hook on src should
// intercept outbound tail calls into tgt.
func (hs *hooksSpec) tailCallMatches(src, plugin string, tgt target) bool {
	targets, filtered := hs.tailCallTargets[src][plugin]
	return !filtered || slices.Contains(targets, tgt)
}

// hook returns the plugin dependency graph for the hook point indicated by
// (target, hookType). Consumers can then add constraints or plugins to this
// dependency graph.
func (hs *hooksSpec) hook(target string, hookType datapathplugins.HookType) *pluginDependencyGraph {
	if hookType == datapathplugins.HookType_EXIT {
		hs.hasExitHooks = true
	}

	if hs.hooks[target] == nil {
		hs.hooks[target] = map[datapathplugins.HookType]*pluginDependencyGraph{
			datapathplugins.HookType_PRE:       {},
			datapathplugins.HookType_POST:      {},
			datapathplugins.HookType_TAIL_CALL: {},
			datapathplugins.HookType_EXIT:      {},
		}
	}

	return hs.hooks[target][hookType]
}

func (hs *hooksSpec) requirePluginStateMap(opts *bpf.CollectionOptions) {
	if !opts.Keep.Has(pluginStateMapName) {
		opts.Keep.Insert(pluginStateMapName)
		opts.CollectionPatches = append(opts.CollectionPatches, func(cs *ebpf.CollectionSpec) error {
			if cs.Maps[pluginStateMapName] == nil {
				cs.Maps[pluginStateMapName] = &ebpf.MapSpec{
					Name:       pluginStateMapName,
					Type:       ebpf.PerCPUArray,
					KeySize:    4,
					ValueSize:  8,
					MaxEntries: 1,
				}
			}
			return nil
		})
	}
}

// instrumentCollection prepares an InstrumentCollectionRequest for each plugin
// that requested hooks and generates a program patch for each program that
// requires instrumentation. It doesn't patch program instructions directly.
// Patching is instead deferred until after reachability analysis and pruning
// happen.
func (hs *hooksSpec) instrumentCollection(cs *ebpf.CollectionSpec, opts *bpf.CollectionOptions) (map[string]*datapathplugins.InstrumentCollectionRequest, map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, error) {
	var err error

	hooks := make(map[string]*datapathplugins.InstrumentCollectionRequest)
	hookSlots := make(map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32)
	opts.ProgramPatches = make(map[string][]func(asm.Instructions) (asm.Instructions, error))
	opts.CollectionPatches = make([]func(*ebpf.CollectionSpec) error, 0)
	if opts.Keep == nil {
		opts.Keep = &set.Set[string]{}
	}

	if hs.hasExitHooks {
		hs.requirePluginStateMap(opts)
		// Tail-called programs with EXIT hooks record their exit dispatcher slot in
		// plugin_state_map and unwind back to the root entrypoint program to execute
		// the exit tail call. Ensure all entrypoint programs (including policy
		// entrypoints) enter instrumentProgram() so they emit the exit-slot handling
		// wrapper even if no hooks target the entrypoint directly.
		for name, prog := range cs.Programs {
			if bpf.IsEntrypoint(prog) && hs.hooks[name] == nil {
				hs.hooks[name] = map[datapathplugins.HookType]*pluginDependencyGraph{
					datapathplugins.HookType_PRE:       {},
					datapathplugins.HookType_POST:      {},
					datapathplugins.HookType_TAIL_CALL: {},
					datapathplugins.HookType_EXIT:      {},
				}
			}
		}
	}

	var callsMap *ebpf.MapSpec
	if cm := bpf.CallsMapSpec(cs); cm != nil {
		callsMap = cm.Copy()
	}

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
		tailcalls, sortErr := hookTypes[datapathplugins.HookType_TAIL_CALL].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_TAIL_CALL, sortErr))

			continue
		}
		exits, sortErr := hookTypes[datapathplugins.HookType_EXIT].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_EXIT, sortErr))

			continue
		}
		if patchErr := hs.instrumentProgram(cs.Programs[hookTarget], pre, post, tailcalls, exits, hooks, hookSlots, opts, callsMap); patchErr != nil {
			err = errors.Join(err, fmt.Errorf("instrumenting %s: %w", hookTarget, patchErr))

			continue
		}
	}

	if callsMap != nil && callsMap.MaxEntries > bpf.CallsMapSpec(cs).MaxEntries {
		opts.CollectionPatches = append(opts.CollectionPatches, func(spec *ebpf.CollectionSpec) error {
			if m := bpf.CallsMapSpec(spec); m != nil {
				m.MaxEntries = callsMap.MaxEntries
			}
			return nil
		})
	}

	return hooks, hookSlots, err
}

func (hs *hooksSpec) instrumentProgram(ps *ebpf.ProgramSpec, pre []string, post []string, tailcalls []string, exits []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest, hookSlots map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, opts *bpf.CollectionOptions, callsMap *ebpf.MapSpec) error {
	if err := hs.instrumentOutboundTailCalls(ps, pre, tailcalls, hooks, hookSlots, opts, callsMap); err != nil {
		return err
	}

	if isPolicyProgram(ps.Name) {
		return hs.instrumentPolicyProgram(ps, pre, exits, hooks, hookSlots, opts, callsMap)
	}

	if err := hs.instrumentExitHooks(ps, exits, hooks, hookSlots, opts, callsMap); err != nil {
		return err
	}

	if bpf.IsTailCall(ps) {
		return hs.injectPreHooksBeforeTailCallProgram(ps, pre, hooks, hookSlots, opts, callsMap)
	}

	return hs.instrumentEntrypointProgram(ps, pre, post, hooks, opts, hs.hasExitHooks, callsMap)
}

// instrumentPolicyProgram orchestrates PRE and EXIT hooks on a policy program (cil_lxc_policy, etc.):
//  1. Relocates the original policy program to a slot in callsMap.
//  2. Builds a policy dispatcher that sits at the original entrypoint.
//  3. If EXIT hooks are present on the policy program, builds an EXIT-hook dispatcher at exitDispatcherSlot.
//  4. Executes PRE hooks in subprograms, invokes the relocated policy program in a subprogram,
//     and tail-calls the exit dispatcher if exit hooks were triggered.
func (hs *hooksSpec) instrumentPolicyProgram(ps *ebpf.ProgramSpec, pre []string, exits []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest, hookSlots map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, opts *bpf.CollectionOptions, callsMap *ebpf.MapSpec) error {
	if len(pre) == 0 && !hs.hasExitHooks {
		return nil
	}

	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	_, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return fmt.Errorf("unable to extract function BTF info for target program %s", ps.Name)
	}

	relocatedSlot := callsMap.MaxEntries
	firstPreSlot := relocatedSlot + 1
	callsMap.MaxEntries += uint32(1 + len(pre))

	exitDispatcherSlot := callsMap.MaxEntries
	firstExitSlot := exitDispatcherSlot + 1
	if len(exits) > 0 {
		callsMap.MaxEntries += uint32(1 + len(exits))
	}

	registerHook := func(pluginName string, hookType datapathplugins.HookType, slot uint32) {
		if hooks[pluginName] == nil {
			hooks[pluginName] = &datapathplugins.InstrumentCollectionRequest{}
		}
		h := &datapathplugins.InstrumentCollectionRequest_Hook{Type: hookType, Target: ps.Name}
		hooks[pluginName].Hooks = append(hooks[pluginName].Hooks, h)
		hookSlots[h] = slot
	}
	for i, plugin := range pre {
		registerHook(plugin, datapathplugins.HookType_PRE, firstPreSlot+uint32(i))
	}
	for i, plugin := range exits {
		registerHook(plugin, datapathplugins.HookType_EXIT, firstExitSlot+uint32(i))
	}

	dispatcherProg, err := buildPolicyDispatcher(ps, callsMap.Name, relocatedSlot, firstPreSlot, pre, hs.hasExitHooks)
	if err != nil {
		return fmt.Errorf("building policy dispatcher for %s: %w", ps.Name, err)
	}
	dispatcherProg.SectionName = ps.SectionName

	relocatedName := "relocated_" + ps.Name
	opts.Keep.Insert(ps.Name)
	opts.Keep.Insert(relocatedName)
	opts.Keep.Insert(dispatcherProg.Name)

	var exitDispatcherProg *ebpf.ProgramSpec
	if len(exits) > 0 {
		exitDispatcherProg, err = buildExitDispatcher(ps, callsMap.Name, exitDispatcherSlot, firstExitSlot, exits)
		if err != nil {
			return fmt.Errorf("building exit dispatcher for %s: %w", ps.Name, err)
		}
		opts.Keep.Insert(exitDispatcherProg.Name)
		opts.ProgramPatches[relocatedName] = append(opts.ProgramPatches[relocatedName], func(insns asm.Instructions) (asm.Instructions, error) {
			return spliceExitHooks(insns, exitDispatcherSlot)
		})
	}

	opts.CollectionPatches = append(opts.CollectionPatches, func(cs *ebpf.CollectionSpec) error {
		target := cs.Programs[ps.Name]
		if target == nil {
			return nil
		}
		btfMeta := btf.FuncMetadata(&target.Instructions[0])
		if btfMeta == nil {
			return fmt.Errorf("unable to extract function BTF info for target program")
		}
		btfMetaCopy := btf.Copy(btfMeta).(*btf.Func)
		btfMetaCopy.Tags = append(btfMetaCopy.Tags, fmt.Sprintf("tail:%s/%d", callsMap.Name, relocatedSlot))
		target.SectionName = resolveSectionName(ps.Type)
		target.Name = relocatedName
		target.Instructions[0] = btf.WithFuncMetadata(target.Instructions[0], btfMetaCopy)

		cs.Programs[target.Name] = target
		cs.Programs[ps.Name] = dispatcherProg
		if exitDispatcherProg != nil {
			cs.Programs[exitDispatcherProg.Name] = exitDispatcherProg
		}
		return nil
	})

	return nil
}

// buildPolicyDispatcher constructs the ebpf.ProgramSpec for a unified PRE and EXIT hook
// dispatcher on a policy program (e.g. cil_lxc_policy, cil_host_policy, cil_lxc_policy_egress).
// The dispatcher sits at the original policy entrypoint, resets state->exit_slot = 0,
// sequentially invokes each registered PRE hook via a subprogram wrapper, invokes the relocated
// policy program in a subprogram wrapper, checks if the policy program or any tail-called
// program exited by inspecting state->exit_slot != 0, and tail-calls the exit dispatcher.
// Something like this:
//
//	int cil_lxc_policy(void *ctx) {
//	    int orig_ret, ret;
//
//	    struct plugin_state *state = bpf_map_lookup_elem(&plugin_state_map, &zero);
//	    if (state)
//	        state->exit_slot = 0;
//
//	    ret = __pre_hook_plugin_a__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//
//	    orig_ret = __target_cil_lxc_policy__(ctx);
//
//	    if (state && state->exit_slot != 0) {
//	        __u32 slot = state->exit_slot;
//	        state->exit_slot = 0;
//	        tail_call(ctx, &cilium_calls, slot);
//	        return DROP; // only reached if the tail call misses
//	    }
//
//	    return orig_ret;
//	}
//
//	static int __pre_hook_plugin_a__(void *ctx) {
//	    tail_call(ctx, &cilium_calls, PLUGIN_A_SLOT);
//	    return CTX_ACT_DROP;
//	}
//
//	static int __target_cil_lxc_policy__(void *ctx) {
//	    tail_call(ctx, &cilium_calls, RELOCATED_SLOT);
//	    return CTX_ACT_DROP;
//	}
func buildPolicyDispatcher(ps *ebpf.ProgramSpec, mapName string, relocatedSlot uint32, firstPreSlot uint32, pre []string, hasExitHooks bool) (*ebpf.ProgramSpec, error) {
	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return nil, fmt.Errorf("unable to extract function BTF info for target program")
	}

	var mainInsns asm.Instructions
	mainInsns = append(mainInsns,
		btf.WithFuncMetadata(
			asm.Mov.Reg(asm.R6, asm.R1).WithSymbol(ps.Name).WithSource(asm.Comment(ps.Name)),
			&btf.Func{
				Name:    ps.Name,
				Linkage: btf.GlobalFunc,
				Type:    funcProto,
			},
		),
	)

	if hasExitHooks {
		// state = bpf_map_lookup_elem(&plugin_state_map, &zero);
		// if (state)
		//     state->exit_slot = 0;
		mainInsns = append(mainInsns, emitClearExitSlot()...)
	}

	var subprogInsns asm.Instructions
	if len(pre) > 0 {
		// Sequentially invoke each registered PRE plugin via dedicated subprogram wrapper
		for i, pluginName := range pre {
			subprogLabel := preHookSubprogName(pluginName)
			pluginSlot := firstPreSlot + uint32(i)
			mainInsns = append(mainInsns,
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Call.Label(subprogLabel),
				asm.JNE.Imm32(asm.R0, retValProceed(ps), "return"),
			)

			subprogInsns = append(subprogInsns, emitWrappedTailCall(subprogLabel, mapName, pluginSlot, ps, funcProto)...)
		}
	}

	if hasExitHooks {
		// Execute target policy in subprogram and capture verdict in R7
		targetSubprogLabel := fmt.Sprintf("__target_%s__", ps.Name)
		mainInsns = append(mainInsns,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Call.Label(targetSubprogLabel),
			asm.Mov.Reg(asm.R7, asm.R0),
		)
		subprogInsns = append(subprogInsns, emitWrappedTailCall(targetSubprogLabel, mapName, relocatedSlot, ps, funcProto)...)

		mainInsns = append(mainInsns, lookupPluginState()...)
		mainInsns = append(mainInsns,
			// If map lookup returned NULL (R0 == 0), jump to exit_fallback
			asm.JEq.Imm(asm.R0, 0, "exit_fallback"),

			// Check if state->exit_slot != 0
			asm.LoadMem(asm.R3, asm.R0, 0, asm.Word),
			asm.JEq.Imm(asm.R3, 0, "return_verdict"),

			// Clear; state->exit_slot = 0
			asm.StoreImm(asm.R0, 0, 0, asm.Word),

			// Tail call to exit dispatcher at slot R3
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.LoadMapPtr(asm.R2, 0).WithReference(mapName),
			asm.FnTailCall.Call(),

			// Fallback if the exit dispatcher tail call misses
			asm.Mov.Imm(asm.R0, retValDrop(ps)).WithSymbol("exit_fallback"),
			asm.Ja.Label("return"),

			asm.Mov.Reg(asm.R0, asm.R7).WithSymbol("return_verdict"),
			asm.Return().WithSymbol("return"),
		)
	} else {
		// Final handoff: static tail call to the relocated target program
		mainInsns = append(mainInsns,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.LoadMapPtr(asm.R2, 0).WithReference(mapName),
			asm.Mov.Imm(asm.R3, int32(relocatedSlot)),
			asm.FnTailCall.Call(),

			// Fallback if final tail call misses
			asm.Mov.Imm(asm.R0, retValDrop(ps)),
			asm.Return().WithSymbol("return"),
		)
	}

	prog := ps.Copy()
	prog.Name = ps.Name
	prog.SectionName = ps.SectionName
	prog.Instructions = append(mainInsns, subprogInsns...)

	return prog, nil
}

// injectPreHooksBeforeTailCallProgram orchestrates PRE hooks on a tail-called program:
// 1. Allocates RelocatedSlot for the original target program.
// 2. Allocates PluginSlots for each PRE plugin.
// 3. Builds the PRE-hook dispatcher to sit at OriginalSlot and registers it in cs.Programs.
// 4. Populates req.Hooks for each PRE plugin.
func (hs *hooksSpec) injectPreHooksBeforeTailCallProgram(ps *ebpf.ProgramSpec, pre []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest, hookSlots map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, opts *bpf.CollectionOptions, callsMap *ebpf.MapSpec) error {
	if len(pre) == 0 {
		return nil
	}

	origSlot, err := bpf.TailCallSlot(ps)
	if err != nil {
		return fmt.Errorf("resolving tail call slot for %s: %w", ps.Name, err)
	}

	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	_, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return fmt.Errorf("unable to extract function BTF info for target program %s", ps.Name)
	}

	relocatedSlot := callsMap.MaxEntries
	firstPluginSlot := relocatedSlot + 1
	callsMap.MaxEntries += uint32(1 + len(pre))

	dispatcherProg, err := buildPreHookDispatcher(ps, callsMap.Name, origSlot, relocatedSlot, firstPluginSlot, pre)
	if err != nil {
		return fmt.Errorf("building PRE dispatcher for %s: %w", ps.Name, err)
	}

	opts.Keep.Insert(dispatcherProg.Name)

	cPatch := func(cs *ebpf.CollectionSpec) error {
		target := cs.Programs[ps.Name]
		if target == nil {
			return nil
		}
		btfMeta := btf.FuncMetadata(&target.Instructions[0])
		if btfMeta == nil {
			return fmt.Errorf("unable to extract function BTF info for target program")
		}
		btfMetaCopy := btf.Copy(btfMeta).(*btf.Func)
		for i, tag := range btfMetaCopy.Tags {
			if strings.HasPrefix(tag, fmt.Sprintf("tail:%s/", callsMap.Name)) {
				btfMetaCopy.Tags[i] = fmt.Sprintf("tail:%s/%d", callsMap.Name, relocatedSlot)
				break
			}
		}
		cs.Programs[dispatcherProg.Name] = dispatcherProg
		target.Instructions[0] = btf.WithFuncMetadata(target.Instructions[0], btfMetaCopy)

		return nil
	}

	opts.CollectionPatches = append(opts.CollectionPatches, cPatch)

	for idx, pluginName := range pre {
		if hooks[pluginName] == nil {
			hooks[pluginName] = &datapathplugins.InstrumentCollectionRequest{}
		}
		h := &datapathplugins.InstrumentCollectionRequest_Hook{
			Type:   datapathplugins.HookType_PRE,
			Target: ps.Name,
		}
		hooks[pluginName].Hooks = append(hooks[pluginName].Hooks, h)
		hookSlots[h] = firstPluginSlot + uint32(idx)
	}

	return nil
}

// buildPreHookDispatcher constructs the ebpf.ProgramSpec for a PRE-hook dispatcher
// on a tail-called program. The dispatcher sits at the target program's original tail
// call map slot, sequentially invokes each registered PRE hook via a subprogram wrapper,
// and concludes with a tail call to the relocated target program. Something like this:
//
//	int pre_dispatcher_<target>(void *ctx) {
//	    int ret;
//
//	    ret = __pre_hook_plugin_a__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ret = __pre_hook_plugin_b__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ...
//	    tail_call(ctx, &cilium_calls, RELOCATED_TARGET_SLOT);
//	    return CTX_ACT_DROP;
//	}
//
//	static int __pre_hook_plugin_a__(void *ctx) {
//	    tail_call(ctx, &cilium_calls, PLUGIN_A_SLOT);
//	    return CTX_ACT_DROP;
//	}
//
//	static int __pre_hook_plugin_b__(void *ctx) {
//	    tail_call(ctx, &cilium_calls, PLUGIN_B_SLOT);
//	    return CTX_ACT_DROP;
//	}
func buildPreHookDispatcher(ps *ebpf.ProgramSpec, mapName string, origSlot uint32, relocatedSlot uint32, firstPluginSlot uint32, plugins []string) (*ebpf.ProgramSpec, error) {
	progName := fmt.Sprintf("%s%s", preHookDispatcherProgPrefix, ps.Name)

	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return nil, fmt.Errorf("unable to extract function BTF info for target program")
	}

	tags := []string{fmt.Sprintf("tail:%s/%d", mapName, origSlot)}

	var mainInsns asm.Instructions
	mainInsns = append(mainInsns,
		btf.WithFuncMetadata(
			asm.Mov.Reg(asm.R6, asm.R1).WithSymbol(progName).WithSource(asm.Comment(progName)),
			&btf.Func{
				Name:    progName,
				Linkage: btf.GlobalFunc,
				Type:    funcProto,
				Tags:    tags,
			},
		),
	)

	var subprogInsns asm.Instructions
	if len(plugins) > 0 {
		// Sequentially invoke each registered PRE plugin via dedicated subprogram wrapper
		for i, pluginName := range plugins {
			subprogLabel := preHookSubprogName(pluginName)
			pluginSlot := firstPluginSlot + uint32(i)
			mainInsns = append(mainInsns,
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Call.Label(subprogLabel),
				asm.JNE.Imm32(asm.R0, retValProceed(ps), "return"),
			)

			subprogInsns = append(subprogInsns, emitWrappedTailCall(subprogLabel, mapName, pluginSlot, ps, funcProto)...)
		}
	}

	// Final handoff: static tail call to the relocated target program
	mainInsns = append(mainInsns,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, 0).WithReference(mapName),
		asm.Mov.Imm(asm.R3, int32(relocatedSlot)),
		asm.FnTailCall.Call(),

		// Fallback if final tail call misses
		asm.Mov.Imm(asm.R0, retValDrop(ps)),
		asm.Return().WithSymbol("return"),
	)

	prog := ps.Copy()
	prog.Name = progName
	prog.SectionName = resolveSectionName(ps.Type)
	prog.Instructions = append(mainInsns, subprogInsns...)

	return prog, nil
}

type target struct {
	mapName string
	slot    uint32
}

type tailCallSite struct {
	insnIdx int
	target  target
}

// instrumentOutboundTailCalls orchestrates outbound TAIL_CALL hooks on a source program:
// 1. Scans the source program's instructions for outbound FnTailCall call sites.
// 2. For each unique static target, allocates DispatcherSlot and PluginSlots in callsMap.
// 3. Builds the Outbound Dispatcher, chaining only the plugins whose tail_call_target filter matches the target, and registers it in cs.Programs. Targets matched by no plugin are left unspliced.
// 4. Populates req.Hooks and hookSlots for each TAIL_CALL plugin.
// 5. Registers a program patch on the source program to splice tail calls to route to the dispatchers.
func (hs *hooksSpec) instrumentOutboundTailCalls(ps *ebpf.ProgramSpec, pre []string, tail []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest, hookSlots map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, opts *bpf.CollectionOptions, callsMap *ebpf.MapSpec) error {
	if len(tail) == 0 {
		return nil
	}

	pluginSlots := make(map[string]uint32, len(tail))
	firstPluginSlot := callsMap.MaxEntries
	callsMap.MaxEntries += uint32(len(tail))
	for idx, pluginName := range tail {
		if hooks[pluginName] == nil {
			hooks[pluginName] = &datapathplugins.InstrumentCollectionRequest{}
		}
		h := &datapathplugins.InstrumentCollectionRequest_Hook{
			Type:   datapathplugins.HookType_TAIL_CALL,
			Target: ps.Name,
		}
		hooks[pluginName].Hooks = append(hooks[pluginName].Hooks, h)
		pluginSlots[pluginName] = firstPluginSlot + uint32(idx)
		hookSlots[h] = pluginSlots[pluginName]
	}

	dispatcherSlots := make(map[target]uint32)
	skipped := make(map[target]bool)
	var calls []tailCallSite

	err := forEachStaticTailCall(ps.Instructions, func(call tailCallSite) error {
		if skipped[call.target] {
			return nil
		}
		slot, exists := dispatcherSlots[call.target]
		if !exists {
			// Preserve the global hook order while dropping plugins whose
			// tail_call_target filter does not match this target.
			plugins := slices.DeleteFunc(slices.Clone(tail), func(pluginName string) bool {
				return !hs.tailCallMatches(ps.Name, pluginName, call.target)
			})
			if len(plugins) == 0 {
				skipped[call.target] = true
				return nil
			}

			slot = callsMap.MaxEntries
			callsMap.MaxEntries++

			dispatcherProg, err := buildOutboundTailCallDispatcher(ps, callsMap.Name, call.target, slot, pluginSlots, plugins)
			if err != nil {
				return fmt.Errorf("building outbound dispatcher for %s to %s/%d: %w", ps.Name, call.target.mapName, call.target.slot, err)
			}

			opts.Keep.Insert(dispatcherProg.Name)
			opts.CollectionPatches = append(opts.CollectionPatches, func(cs *ebpf.CollectionSpec) error {
				cs.Programs[dispatcherProg.Name] = dispatcherProg
				return nil
			})
			dispatcherSlots[call.target] = slot
		}
		calls = append(calls, call)
		return nil
	})
	if err != nil {
		return fmt.Errorf("instrumenting outbound tail calls in %s: %w", ps.Name, err)
	}

	if len(calls) == 0 {
		return nil
	}

	targetName := ps.Name
	if isPolicyProgram(ps.Name) && (len(pre) > 0 || hs.hasExitHooks) {
		targetName = "relocated_" + ps.Name
	}

	opts.ProgramPatches[targetName] = append(opts.ProgramPatches[targetName], func(insns asm.Instructions) (asm.Instructions, error) {
		return spliceOutboundTailCalls(insns, callsMap.Name, calls, dispatcherSlots), nil
	})

	return nil
}

// buildOutboundTailCallDispatcher constructs the ebpf.ProgramSpec for an outbound static
// tail-call dispatcher. When a program performs an outbound tail call: (1) The call site is
// rewritten to tail-call dispatcherSlot instead, (2) the dispatcher sequentially invokes each
// registered TAIL_CALL plugin hook via a subprogram wrapper, and concludes with a static tail
// call to origSlot in targetMap.
//
//	int outbound_static_dispatcher_<target>_to_<origSlot>(void *ctx) {
//	    int ret;
//
//	    ret = __tail_call_hook_plugin_a__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ret = __tail_call_hook_plugin_b__(ctx);
//	    if (ret != RET_PROCEED)
//	        return ret;
//	    ...
//	    tail_call(ctx, &prog_array, ORIG_SLOT);
//	    return CTX_ACT_DROP;
//	}
//
//	static int __tail_call_hook_plugin_a__(void *ctx) {
//	    tail_call(ctx, &prog_array, PLUGIN_A_SLOT);
//	    return RET_PROCEED;
//	}
//
//	static int __tail_call_hook_plugin_b__(void *ctx) {
//	    tail_call(ctx, &prog_array, PLUGIN_B_SLOT);
//	    return RET_PROCEED;
//	}
func buildOutboundTailCallDispatcher(ps *ebpf.ProgramSpec, mapName string, tgt target, dispatcherSlot uint32, pluginSlots map[string]uint32, plugins []string) (*ebpf.ProgramSpec, error) {
	progName := fmt.Sprintf("%s%s_to_%s_%d", staticTailCallHookDispatcherProgPrefix, ps.Name, tgt.mapName, tgt.slot)

	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return nil, fmt.Errorf("unable to extract function BTF info for target program")
	}

	var mainInsns asm.Instructions
	mainInsns = append(mainInsns,
		btf.WithFuncMetadata(
			asm.Mov.Reg(asm.R6, asm.R1).WithSymbol(progName).WithSource(asm.Comment(progName)),
			&btf.Func{
				Name:    progName,
				Linkage: btf.GlobalFunc,
				Type:    funcProto,
				Tags:    []string{fmt.Sprintf("tail:%s/%d", mapName, dispatcherSlot)},
			},
		),
	)

	var subprogInsns asm.Instructions
	if len(plugins) > 0 {
		// Sequentially invoke each registered TAIL_CALL plugin via a dedicated subprogram wrapper
		for _, pluginName := range plugins {
			subprogLabel := staticTailCallHookSubprogName(pluginName, tgt.slot)
			pluginSlot := pluginSlots[pluginName]

			mainInsns = append(mainInsns,
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Call.Label(subprogLabel),
				asm.JNE.Imm32(asm.R0, retValProceed(ps), "return"),
			)

			subprogInsns = append(subprogInsns, emitWrappedTailCall(subprogLabel, mapName, pluginSlot, ps, funcProto)...)
		}
	}

	// Final onward tail call (static immediate slot)
	mainInsns = append(mainInsns,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, 0).WithReference(tgt.mapName),
		asm.Mov.Imm(asm.R3, int32(tgt.slot)),
		asm.FnTailCall.Call(),

		// Fallback if final tail call misses
		asm.Mov.Imm(asm.R0, retValDrop(ps)),
		asm.Return().WithSymbol("return"),
	)

	prog := ps.Copy()
	prog.Name = progName
	prog.SectionName = resolveSectionName(ps.Type)
	prog.Instructions = append(mainInsns, subprogInsns...)

	return prog, nil
}

func spliceOutboundTailCalls(insns asm.Instructions, callsMapName string, calls []tailCallSite, dispatcherSlots map[target]uint32) asm.Instructions {
	for _, call := range calls {
		slot := dispatcherSlots[call.target]
		insns[call.insnIdx-1].Constant = int64(slot)
		insns[call.insnIdx-2] = insns[call.insnIdx-2].WithReference(callsMapName)
	}
	return insns
}

// instrumentExitHooks orchestrates EXIT hooks on a target program:
// 1. Ensures plugin_state_map is present in cs.Maps.
// 2. Allocates a DispatcherSlot in cilium_calls and PluginSlots for each EXIT plugin.
// 3. Builds the EXIT-hook dispatcher and registers it in cs.Programs.
// 4. Splices the target program's EXIT instructions to jump to an exit epilogue.
// 5. Populates req.Hooks for each EXIT plugin.
func (hs *hooksSpec) instrumentExitHooks(ps *ebpf.ProgramSpec, exit []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest, hookSlots map[*datapathplugins.InstrumentCollectionRequest_Hook]uint32, opts *bpf.CollectionOptions, callsMap *ebpf.MapSpec) error {
	if len(exit) == 0 {
		return nil
	}

	dispatcherSlot := callsMap.MaxEntries
	firstPluginSlot := dispatcherSlot + 1
	callsMap.MaxEntries += uint32(1 + len(exit))

	dispatcherProg, err := buildExitDispatcher(ps, callsMap.Name, dispatcherSlot, firstPluginSlot, exit)
	if err != nil {
		return fmt.Errorf("building exit dispatcher for %s: %w", ps.Name, err)
	}

	opts.Keep.Insert(dispatcherProg.Name)
	opts.CollectionPatches = append(opts.CollectionPatches, func(cs *ebpf.CollectionSpec) error {
		cs.Programs[dispatcherProg.Name] = dispatcherProg
		return nil
	})

	for idx, pluginName := range exit {
		if hooks[pluginName] == nil {
			hooks[pluginName] = &datapathplugins.InstrumentCollectionRequest{}
		}
		h := &datapathplugins.InstrumentCollectionRequest_Hook{
			Type:   datapathplugins.HookType_EXIT,
			Target: ps.Name,
		}
		hooks[pluginName].Hooks = append(hooks[pluginName].Hooks, h)
		hookSlots[h] = firstPluginSlot + uint32(idx)
	}

	opts.ProgramPatches[ps.Name] = append(opts.ProgramPatches[ps.Name], func(insns asm.Instructions) (asm.Instructions, error) {
		return spliceExitHooks(insns, dispatcherSlot)
	})

	return nil
}

// buildExitDispatcher constructs the ebpf.ProgramSpec for an EXIT-hook dispatcher.
// When an instrumented program returns, its exit point writes the original return
// value to plugin_state_map and tail-calls the exit dispatcher at dispatcherSlot.
// The exit dispatcher retrieves the original return value, sequentially invokes
// each registered EXIT plugin hook via a subprogram wrapper, and returns either a
// non-proceed verdict from a hook or the original program's return value. Something like this:
//
//	int exit_dispatcher_<target>(void *ctx) {
//	    struct plugin_state *state = bpf_map_lookup_elem(&plugin_state_map, &zero);
//	    if (!state)
//	        return RET_PROCEED;
//
//	    int orig_ret = state->orig_ret;
//	    int ret;
//
//	    ret = __exit_hook_plugin_a__(ctx);
//	    if (ret != -1)
//	        return ret;
//	    ret = __exit_hook_plugin_b__(ctx);
//	    if (ret != -1)
//	        return ret;
//	    ...
//	    return orig_ret;
//	}
//
//	static int __exit_hook_plugin_a__(void *ctx) {
//	    tail_call(ctx, &cilium_calls, PLUGIN_A_SLOT);
//	    return -1;
//	}
//
//	static int __exit_hook_plugin_b__(void *ctx) {
//	    tail_call(ctx, &cilium_calls, PLUGIN_B_SLOT);
//	    return -1;
//	}
func buildExitDispatcher(ps *ebpf.ProgramSpec, mapName string, dispatcherSlot uint32, firstPluginSlot uint32, plugins []string) (*ebpf.ProgramSpec, error) {
	progName := fmt.Sprintf("%s%s", exitHookDispatcherProgPrefix, ps.Name)

	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return nil, fmt.Errorf("unable to extract function BTF info for target program")
	}

	var mainInsns asm.Instructions
	mainInsns = append(mainInsns,
		btf.WithFuncMetadata(
			asm.Mov.Reg(asm.R6, asm.R1).WithSymbol(progName).WithSource(asm.Comment(progName)),
			&btf.Func{
				Name:    progName,
				Linkage: btf.GlobalFunc,
				Type:    funcProto,
				Tags:    []string{fmt.Sprintf("tail:%s/%d", mapName, dispatcherSlot)},
			},
		),
	)

	mainInsns = append(mainInsns, lookupPluginState()...)
	mainInsns = append(mainInsns,
		// If map lookup returned NULL (R0 == 0), jump to exit_fallback
		asm.JEq.Imm(asm.R0, 0, "exit_fallback"),

		// Retrieve original return verdict from state->orig_ret (offset 4) into callee-saved R7
		asm.LoadMem(asm.R7, asm.R0, 4, asm.Word),
	)

	var subprogInsns asm.Instructions
	if len(plugins) > 0 {
		for i, pluginName := range plugins {
			subprogLabel := exitHookSubprogName(pluginName)
			pluginSlot := firstPluginSlot + uint32(i)

			mainInsns = append(mainInsns,
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Call.Label(subprogLabel),
				asm.JNE.Imm32(asm.R0, retValProceed(ps), "return"),
			)

			subprogInsns = append(subprogInsns, emitWrappedTailCall(subprogLabel, mapName, pluginSlot, ps, funcProto)...)
		}
	}

	mainInsns = append(mainInsns,
		asm.Mov.Reg(asm.R0, asm.R7),
		asm.Ja.Label("return"),

		asm.Mov.Imm(asm.R0, retValDrop(ps)).WithSymbol("exit_fallback"),
		asm.Return().WithSymbol("return"),
	)

	prog := ps.Copy()
	prog.Name = progName
	prog.SectionName = resolveSectionName(ps.Type)
	prog.Instructions = append(mainInsns, subprogInsns...)

	return prog, nil
}

// spliceExitHooks rewrites EXIT instructions in program spec with jumps to an exit epilogue
// that records dispatcherSlot into offset 0 of plugin_state_map.
//
// The epilogue is inserted at the end of the root function rather than at the end of the
// instruction stream. After [ebpf-go flattens a program], the stream holds the entrypoint
// followed by every out-of-line bpf2bpf subprogram it calls (e.g. helpers declared
// __noinline, which the compiler emits into .text), each introduced by its own btf.Func:
//
//	[0..rootEnd)      root function
//	[rootEnd..len)    out-of-line subprograms
//
// The kernel partitions a program into subprograms using BTF func_info (check_subprogs in
// kernel/bpf/verifier.c) and rejects any jump whose target lands outside the jumping
// instruction's own subprogram. Appending the epilogue to the end of the stream would place
// it inside the *last* subprogram, turning every rewritten return in the root into an
// out-of-range jump.
func spliceExitHooks(insns asm.Instructions, dispatcherSlot uint32) (asm.Instructions, error) {
	rootFunc := btf.FuncMetadata(&insns[0])
	inRootFunc := true
	hasExit := false
	rootEnd := -1

	for i := range insns {
		ins := &insns[i]
		if fn := btf.FuncMetadata(ins); fn != nil {
			if rootFunc != nil {
				inRootFunc = (fn == rootFunc)
			} else {
				inRootFunc = (i == 0)
			}
			if !inRootFunc && rootEnd < 0 {
				rootEnd = i
			}
		}
		if inRootFunc && ins.OpCode == asm.Return().OpCode {
			hasExit = true
			sym := ins.Symbol()
			jumpIns := asm.Ja.Label("exit_epilogue")
			if sym != "" {
				jumpIns = jumpIns.WithSymbol(sym)
			}
			insns[i] = jumpIns
		}
	}
	if !hasExit {
		return insns, nil
	}
	if rootEnd < 0 {
		rootEnd = len(insns)
	}

	var epilogue asm.Instructions
	epilogue = append(epilogue,
		asm.Mov.Reg(asm.R8, asm.R0).WithSymbol("exit_epilogue"),
	)
	epilogue = append(epilogue, lookupPluginState()...)
	epilogue = append(epilogue,
		// If map lookup returned NULL (R0 == 0), jump back to original fall-through path
		asm.JEq.Imm(asm.R0, 0, "skip_record"),
		asm.StoreImm(asm.R0, 0, int64(dispatcherSlot), asm.Word),
		asm.StoreMem(asm.R0, 4, asm.R8, asm.Word),

		// Save orig_ret into R0 and exit
		asm.Mov.Reg(asm.R0, asm.R8).WithSymbol("skip_record"),
		asm.Return(),
	)

	out := make(asm.Instructions, 0, len(insns)+len(epilogue))
	out = append(out, insns[:rootEnd]...)
	out = append(out, epilogue...)
	out = append(out, insns[rootEnd:]...)

	return out, nil
}

// instrumentEntrypointProgram generates a program patcher that prepends a dispatcher that
// invokes pre-program hooks, then invokes the original program, checks for triggered EXIT hooks,
// and finally invokes post-program hooks. Something like this:
//
//	int dispatch(void *ctx) {
//	    int orig_ret, ret;
//
//	    // Only emitted when the collection has EXIT hooks:
//	    struct plugin_state *state = bpf_map_lookup_elem(&plugin_state_map, &zero);
//	    if (state)
//	        state->exit_slot = 0;
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
//	    // Only emitted when the collection has EXIT hooks:
//	    state = bpf_map_lookup_elem(&plugin_state_map, &zero);
//	    if (state && state->exit_slot != 0) {
//	        __u32 slot = state->exit_slot;
//	        ret = do_exit_tail_call(ctx, slot);
//	        if (ret != RET_PROCEED)
//	            orig_ret = ret;
//	    }
//
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
//	int do_exit_tail_call(void *ctx, __u32 slot) {
//	    bpf_tail_call(ctx, &cilium_calls, slot);
//	    return CTX_ACT_DROP;
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
func (hs *hooksSpec) instrumentEntrypointProgram(ps *ebpf.ProgramSpec, pre []string, post []string, hooks map[string]*datapathplugins.InstrumentCollectionRequest, opts *bpf.CollectionOptions, hasExitHooks bool, callsMap *ebpf.MapSpec) error {
	if len(pre) == 0 && len(post) == 0 && !hasExitHooks {
		return nil
	}

	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return fmt.Errorf("unable to extract function BTF info for target program")
	}

	var prologue asm.Instructions

	// Preserve ctx in R6, callee saved register.
	prologue = append(prologue, asm.Mov.Reg(asm.R6, asm.R1))

	if hasExitHooks {
		// state = bpf_map_lookup_elem(&plugin_state_map, &zero);
		// if (state)
		//     state->exit_slot = 0;
		prologue = append(prologue, emitClearExitSlot()...)
	}

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

	if hasExitHooks {
		// state = bpf_map_lookup_elem(&plugin_state_map, &zero);
		// if (state && state->exit_slot != 0) {
		//     __u32 slot = state->exit_slot;
		//     ret = do_exit_tail_call(ctx, slot);
		//     if (ret != RET_VAL_PROCEED)
		//         orig_ret = ret;
		// }
		subprogLabel := "do_exit_tail_call_" + ps.Name
		prologue = append(prologue, lookupPluginState()...)
		prologue = append(prologue,
			// If map lookup returned NULL (R0 == 0), jump to exit_fallback
			asm.JEq.Imm(asm.R0, 0, "exit_fallback"),

			// Check if state->exit_slot != 0
			asm.LoadMem(asm.R2, asm.R0, 0, asm.Word),
			asm.JEq.Imm(asm.R2, 0, "skip_exit"),

			// Invoke exit tail call dispatcher in subprogram wrapper
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Call.Label(subprogLabel),

			// If exit hook overrides return verdict, update orig_ret in R7
			asm.JEq.Imm(asm.R0, retValProceed(ps), "skip_exit"),
			asm.Mov.Reg(asm.R7, asm.R0),

			asm.Mov.Reg(asm.R6, asm.R6).WithSymbol("skip_exit"),
		)
	}

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

	if hasExitHooks {
		prologue = append(prologue,
			asm.Mov.Imm(asm.R0, retValDrop(ps)).WithSymbol("exit_fallback"),
			asm.Ja.Label("return"),
		)
	}

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

	if hasExitHooks {
		// int do_exit_tail_call(void *ctx, __u32 slot) {
		//     bpf_tail_call(ctx, &cilium_calls, slot);
		//     return CTX_ACT_DROP;
		// }
		subprogLabel := "do_exit_tail_call_" + ps.Name
		epilogue = append(epilogue,
			btf.WithFuncMetadata(
				asm.Mov.Reg(asm.R3, asm.R2).WithSymbol(subprogLabel).WithSource(asm.Comment(subprogLabel)),
				&btf.Func{
					Name:    subprogLabel,
					Linkage: btf.StaticFunc,
					Type: &btf.FuncProto{
						Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
					},
				},
			),
			asm.LoadMapPtr(asm.R2, 0).WithReference(callsMap.Name),
			asm.FnTailCall.Call(),
			asm.Mov.Imm(asm.R0, retValDrop(ps)),
			asm.Return(),
		)
	}

	opts.ProgramPatches[ps.Name] = append(opts.ProgramPatches[ps.Name], func(insns asm.Instructions) (asm.Instructions, error) {
		return append(prologue, append(insns, epilogue...)...), nil
	})

	return nil
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

func emitWrappedTailCall(subprogLabel string, mapName string, slot uint32, ps *ebpf.ProgramSpec, funcProto *btf.FuncProto) asm.Instructions {
	return asm.Instructions{
		btf.WithFuncMetadata(
			asm.LoadMapPtr(asm.R2, 0).WithReference(mapName).WithSymbol(subprogLabel).WithSource(asm.Comment(subprogLabel)),
			&btf.Func{
				Name:    subprogLabel,
				Linkage: btf.GlobalFunc,
				Type:    funcProto,
			},
		),
		asm.Mov.Imm(asm.R3, int32(slot)),
		asm.FnTailCall.Call(),

		// If tail call misses, return drop code
		asm.Mov.Imm(asm.R0, retValDrop(ps)),
		asm.Return(),
	}
}

func lookupPluginState() asm.Instructions {
	return asm.Instructions{
		// Lookup plugin_state_map (key = 0) on stack: fp - 8 = 0
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -8),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference(pluginStateMapName),
		asm.FnMapLookupElem.Call(),
	}
}

func emitClearExitSlot() asm.Instructions {
	insns := lookupPluginState()
	return append(insns,
		// If map lookup returned NULL (R0 == 0), skip the store.
		asm.JEq.Imm(asm.R0, 0, "skip_clear"),
		asm.StoreImm(asm.R0, 0, 0, asm.Word),
		asm.Mov.Reg(asm.R6, asm.R6).WithSymbol("skip_clear"),
	)
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

func retValDrop(ps *ebpf.ProgramSpec) int32 {
	switch ps.Type {
	case ebpf.XDP:
		return 1 // XDP_DROP
	case ebpf.SchedCLS, ebpf.SchedACT:
		return 2 // TC_ACT_SHOT
	default:
		return 0 // SYS_REJECT
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

func resolveSectionName(targetType ebpf.ProgramType) string {
	switch targetType {
	case ebpf.XDP:
		return "xdp/tail"
	default:
		return "classifier/tail"
	}
}

func forEachStaticTailCall(insns asm.Instructions, cb func(call tailCallSite) error) error {
	const (
		stateStart int = iota
		stateR1Load
		stateR2Load
		stateR3Load
	)
	state := stateStart
	var mapName string
	var slot uint32

	for i := range insns {
		insn := &insns[i]

		if insn.Dst == asm.R1 && (insn.OpCode.ALUOp() == asm.Mov || insn.OpCode.Class().IsLoad()) {
			state = stateR1Load
			continue
		}

		switch state {
		case stateR1Load:
			if insn.Dst == asm.R2 && insn.IsLoadFromMap() && insn.Reference() != "" {
				mapName = insn.Reference()
				state = stateR2Load
				continue
			}
		case stateR2Load:
			if insn.Dst == asm.R3 && insn.OpCode.ALUOp() == asm.Mov && insn.OpCode.Source() == asm.ImmSource {
				slot = uint32(insn.Constant)
				state = stateR3Load
				continue
			}
		case stateR3Load:
			if insn.IsBuiltinCall() && insn.Constant == int64(asm.FnTailCall) {
				tgt := target{
					mapName: mapName,
					slot:    slot,
				}
				if err := cb(tailCallSite{insnIdx: i, target: tgt}); err != nil {
					return err
				}
			}
		}

		state = stateStart
		mapName = ""
		slot = 0
	}

	return nil
}
