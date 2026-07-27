// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	_ "embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"

	_ "github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	ErrStarted     = errors.New("registry has already been started")
	ErrNotStarted  = errors.New("registry has not yet been started")
	ErrMapNotFound = errors.New("MapSpec not found")
)

// MapRegistry contains [ebpf.MapSpec]s for all pinned maps in the datapath.
//
// The registry allows Cells to provide [MapSpecPatch]es during Hive
// construction, e.g. for changing MaxEntries of a map based on configuration
// parameters. Only select fields can be modified, see [MapSpecPatch] for
// details.
//
// Once the registry has been started, MapSpecs can only be retrieved but
// not modified. Any packages which need to create maps at runtime should
// obtain the MapSpecs from this registry.
type MapRegistry struct {
	l *slog.Logger

	mu      lock.Mutex
	started bool

	specs   map[string]*ebpf.MapSpec
	patches map[string]*MapSpecPatch
}

// new returns a new MapRegistry and populates it with compile-time MapSpecs.
func new(log *slog.Logger) (*MapRegistry, error) {
	specs, err := maps.LoadMapSpecs()
	if err != nil {
		return nil, err
	}

	return &MapRegistry{
		l:       log,
		specs:   specs,
		patches: make(map[string]*MapSpecPatch),
	}, nil
}

// start the registry, making it read-only.
func (r *MapRegistry) start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return fmt.Errorf("starting registry: %w", ErrStarted)
	}

	r.started = true

	return nil
}

// Modify allows modifying the MapSpec for the given map name. Must be called
// during Hive construction in [cell.Provide] or [cell.Invoke], otherwise
// returns [ErrStarted].
//
// Returns [ErrMapNotFound] if no map with the given name exists.
func (r *MapRegistry) Modify(name string, modify func(*MapSpecPatch)) error {
	if modify == nil {
		return fmt.Errorf("modify function cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return ErrStarted
	}

	spec, ok := r.specs[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMapNotFound, name)
	}

	// Retrieve existing patch or create a new one based on the MapSpec.
	patch, ok := r.patches[name]
	if !ok {
		patch = newMapSpecPatch(spec)
	}

	// Create two patches, allow one to be modified by the caller.
	mod := patch.copy()

	modify(mod)

	// Log diff if any changes were made and merge patch into the registry for
	// Cells to retrieve for map creation.
	if diff := patch.diff(mod); diff != "" {
		r.l.Info("MapSpec modified",
			logfields.BPFMapName, name,
			logfields.Changes, diff)

		mod.Apply(spec)
	}

	// Store the patch regardless of whether any changes were made so the loader
	// can track which MapSpecs have opted into modification through the registry.
	// Copy before storing to prevent callers from modifying retained patches.
	r.patches[name] = mod.copy()

	return nil
}

// Get returns a copy of the MapSpec for the given map name. Must be called
// during Hive start in [cell.Lifecycle.Start] or [cell.Hook.OnStart], otherwise
// returns [ErrNotStarted].
//
// Returns [ErrMapNotFound] if no map with the given name exists.
func (r *MapRegistry) Get(name string) (*ebpf.MapSpec, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		return nil, ErrNotStarted
	}

	spec, ok := r.specs[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMapNotFound, name)
	}

	return spec.Copy(), nil
}

// GetPatch returns a [MapSpecPatch] for the given map name if
// [MapRegistry.Modify] was called by a Cell during startup. Must be called
// during Hive start in [cell.Lifecycle.Start] or [cell.Hook.OnStart], otherwise
// returns [ErrNotStarted].
//
// This is intended for the loader to apply patches during Collection loading.
//
// Returns [ErrMapNotFound] if no map with the given name exists or if
// [MapRegistry.Modify] was not called for the map.
func (r *MapRegistry) GetPatch(name string) (*MapSpecPatch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		return nil, ErrNotStarted
	}

	patch, ok := r.patches[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMapNotFound, name)
	}

	return patch.copy(), nil
}
