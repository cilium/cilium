// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// A Plugin represents a registered datapath plugin and its client.
type Plugin interface {
	datapathplugins.DatapathPluginClient
	// Name returns the name of this datapath plugin.
	Name() string
	// AttachmentPolicy returns the attachment policy for this plugin.
	AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
	// DeepEqual returns true if this plugin is equivalent to o.
	DeepEqual(o Plugin) bool
}

// Plugins is a mapping between plugin names and Plugins.
type Plugins map[string]Plugin

// DeepEqual returns true if all plugins are equal to those in o.
func (p *Plugins) DeepEqual(o *Plugins) bool {
	if p == nil {
		return o == nil
	} else if o == nil {
		return false
	}

	if len(*p) != len(*o) {
		return false
	}

	for name, plugin := range *p {
		if _, ok := (*o)[name]; !ok {
			return false
		}
		if !plugin.DeepEqual((*o)[name]) {
			return false
		}
	}

	return true
}

// Registry contains all registered datapath plugins.
type Registry interface {
	// Register registers a plugin and sets up a client to talk to it.
	Register(dpp *api_v2alpha1.CiliumDatapathPlugin)
	// Unregister unregisters a plugin and shuts down its client.
	Unregister(dpp *api_v2alpha1.CiliumDatapathPlugin)
	// Plugins returns a snapshot of the current state of the registry.
	Plugins() Plugins
	// Sync blocks until the registry is initialized or until ctx is done.
	Sync(ctx context.Context) error
}

// CollectionHookStatus contains details about how a collection was instrumented
// by plugin hooks. CollectionHookStatus is meant to be built incrementally as
// the collection load sequence progresses:
//
//  1. At the start of a collection load sequence the loader creates a new
//     instance of CollectionHookStatus.
//  2. After receiving responses from all PrepareCollection requests, the loader
//     calls RecordHook() for each hook requested by a plugin recording the
//     plugin names, hook types, and ordering constraints.
//  3. After finalizing the set of hooks and their order, the loader calls
//     RecordHookOrder() to record the final position of each hook.
//  4. After loading the collection into the kernel, the loader calls
//     RecordTargetProgramIDs() to record the final program ID for each of the
//     instrumented programs.
//  5. Finally, after plugins load their hook programs and the loader receives
//     all InstrumentCollection responses, the loader calls RecordHookProgramID()
//     for each hook to record the final program ID and program name for the hook
//     program.
type CollectionHookStatus struct {
	// AttachmentContext uniquely identifies the collection type and attachment
	// point for this collection. It may be used as a primary key in a collection
	// of CollectionHookStatus objects.
	AttachmentContext *datapathplugins.AttachmentContext
	// Programs is a sparsely-allocated map containing information about all
	// the programs instrumented by plugins.
	Programs map[string]*ProgramHookStatus
}

// OrderedTargetNames returns an iterator that yields all instrumented program
// names in lexicographical order.
func (c *CollectionHookStatus) OrderedTargetNames() iter.Seq[string] {
	return func(yield func(string) bool) {
		targetNames := slices.Collect(maps.Keys(c.Programs))
		slices.Sort(targetNames)

		for _, targetName := range targetNames {
			if !yield(targetName) {
				return
			}
		}
	}
}

// ProgramHookStatus contains information about a program that was instrumented
// by plugins.
type ProgramHookStatus struct {
	// ID is the program ID.
	ID ebpf.ProgramID
	// Hooks contains information about all the hooks attached to this program
	// organized by (hook type, plugin name)
	Hooks map[datapathplugins.HookType]map[string]*HookInfo
}

// OrderedHookTypes returns an iterator that yields all hook types attached to
// this program in a deterministic order.
func (p *ProgramHookStatus) OrderedHookTypes() iter.Seq[datapathplugins.HookType] {
	return func(yield func(datapathplugins.HookType) bool) {
		hookTypes := slices.Collect(maps.Keys(p.Hooks))
		slices.Sort(hookTypes)

		for _, hookType := range hookTypes {
			if !yield(hookType) {
				return
			}
		}
	}
}

// OrderedPlugins returns an iterator that yields the name of all plugins that
// attached a hook of type hookType in attachment order.
func (p *ProgramHookStatus) OrderedPlugins(hookType datapathplugins.HookType) iter.Seq[string] {
	return func(yield func(string) bool) {
		pluginNames := slices.Collect(maps.Keys(p.Hooks[hookType]))
		slices.SortFunc(pluginNames, func(a, b string) int {
			return p.Hooks[hookType][a].Position - p.Hooks[hookType][b].Position
		})

		for _, pluginName := range pluginNames {
			if !yield(pluginName) {
				return
			}
		}
	}
}

// HookInfo contains information about a hook program.
type HookInfo struct {
	// ProgramID is the hook program ID.
	ProgramID ebpf.ProgramID
	// ProgramName is the hook program name.
	ProgramName string
	// Constraints are the ordering constraints provided by the plugin when
	// setting up this hook.
	Constraints []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint
	// Position represents the final attachment order relative to other plugins at
	// the same hook point.
	Position int
}

// NewCollectionStatus creates a new CollectionHookStatus with an empty
// Programs map and with AttachmentContext set to ac.
func NewCollectionHookStatus(ac *datapathplugins.AttachmentContext) *CollectionHookStatus {
	return &CollectionHookStatus{
		AttachmentContext: ac,
		Programs:          make(map[string]*ProgramHookStatus),
	}
}

// TableHeader implements statedb.TableWritable.
func (c *CollectionHookStatus) TableHeader() []string {
	return []string{
		"Device",
		"Pod",
		"Instrumented Programs",
	}
}

// TableRow implements statedb.TableWritable.
func (c *CollectionHookStatus) TableRow() []string {
	return []string{
		c.AttachmentContext.GetDevice(),
		c.PodNamespaceName(),
		fmt.Sprintf("%d", c.hookCount()),
	}
}

// PodNamespaceName returns "$POD_NAMESPACE/$POD_NAME" if the attachment
// context is related to a pod; otherwise, it returns an empty string "".
func (c *CollectionHookStatus) PodNamespaceName() string {
	if c.AttachmentContext.GetLxc().GetPodInfo().GetNamespace() == "" && c.AttachmentContext.GetLxc().GetPodInfo().GetName() == "" {
		return ""
	}

	return fmt.Sprintf("%s/%s", c.AttachmentContext.GetLxc().GetPodInfo().GetNamespace(), c.AttachmentContext.GetLxc().GetPodInfo().GetName())
}

func (c *CollectionHookStatus) hookCount() int {
	var hookCount int

	for _, targetHooksInfo := range c.Programs {
		for _, hooks := range targetHooksInfo.Hooks {
			hookCount += len(hooks)
		}
	}

	return hookCount
}

// RecordHook initializes an entry at c.Programs[target].Hooks[hookType][plugin]
// with Constraints set to constraints.
func (c *CollectionHookStatus) RecordHook(target string, hookType datapathplugins.HookType, plugin string, constraints []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint) {
	if c.Programs[target] == nil {
		c.Programs[target] = &ProgramHookStatus{
			Hooks: map[datapathplugins.HookType]map[string]*HookInfo{},
		}
	}

	if c.Programs[target].Hooks[hookType] == nil {
		c.Programs[target].Hooks[hookType] = map[string]*HookInfo{}
	}

	c.Programs[target].Hooks[hookType][plugin] = &HookInfo{
		Constraints: constraints,
	}
}

// RecordHookOrder sets Position for each entry in
// c.Programs[target].Hooks[hookType] to the index of the plugin name in
// plugins. Plugins represents the final order of attachments for hookType at
// the target program.
func (c *CollectionHookStatus) RecordHookOrder(target string, hookType datapathplugins.HookType, plugins []string) error {
	if len(plugins) == 0 {
		return nil
	}

	if c.Programs[target] == nil {
		return fmt.Errorf("unknown target %s", target)
	}

	if c.Programs[target].Hooks[hookType] == nil {
		return fmt.Errorf("unknown hook type %s for target %s", hookType, target)
	}

	for i, p := range plugins {
		if c.Programs[target].Hooks[hookType][p] == nil {
			return fmt.Errorf("unknown plugin %s for hook type %s at target %s", p, hookType, target)
		}

		c.Programs[target].Hooks[hookType][p].Position = i
	}

	return nil
}

// RecordTargetProgramIDs records the ID of each target program.
func (c *CollectionHookStatus) RecordTargetProgramIDs(coll *ebpf.Collection) error {
	for name, state := range c.Programs {
		prog := coll.Programs[name]
		if prog == nil {
			return fmt.Errorf("program %s does not exist", name)
		}

		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("getting program info for %s: %w", name, err)
		}

		id, _ := info.ID()
		state.ID = ebpf.ProgramID(id)
	}

	return nil
}

// RecordHookProgramInfo records the ID and name of the specified hook program.
func (c *CollectionHookStatus) RecordHookProgramInfo(target string, hookType datapathplugins.HookType, plugin string, prog *ebpf.Program) error {
	if c.Programs[target] == nil {
		return fmt.Errorf("unknown target %s", target)
	}

	if c.Programs[target].Hooks[hookType] == nil {
		return fmt.Errorf("unknown hook type %s for target %s", hookType, target)
	}

	if c.Programs[target].Hooks[hookType][plugin] == nil {
		return fmt.Errorf("unknown plugin %s for hook type %s at target %s", plugin, hookType, target)
	}

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("getting hook program info: %w", err)
	}

	id, _ := info.ID()
	c.Programs[target].Hooks[hookType][plugin].ProgramID = id
	c.Programs[target].Hooks[hookType][plugin].ProgramName = info.Name

	return nil
}

// HookStatusWriter represents a collection of CollectionHookStatus objects.
type HooksStatusWriter interface {
	// Upsert inserts or updates the CollectionHookStatus uniquely identified
	// by collHookStatus.AttachmentContext.
	Upsert(collHookStatus *CollectionHookStatus)
	// Purge deletes the CollectionHookStatus uniquely identified ac if one
	// exists.
	Purge(ac *datapathplugins.AttachmentContext)
}
