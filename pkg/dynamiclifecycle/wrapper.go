// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamiclifecycle

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/lock"
)

type featureRegistration struct {
	Name      DynamicFeatureName
	Deps      []DynamicFeatureName
	Lifecycle *Lifecycle
}
type featureRegistrationOut struct {
	cell.Out
	FeatureRegistration featureRegistration `group:"dynamiclifecycle-registrations"`
}

// Lifecycle provides a wrapper over the cell.Lifecycle
// which only allows appending hooks and performing get on them.
type Lifecycle struct {
	Hooks []cell.HookInterface // Lifecycle hooks
	m     lock.Mutex
}

func (l *Lifecycle) Append(hook cell.HookInterface) {
	l.m.Lock()
	defer l.m.Unlock()
	l.Hooks = append(l.Hooks, hook)
}

func (l *Lifecycle) Start(sl *slog.Logger, _ context.Context) error {
	sl.Error("Start() should not be called, lifecycle managed by Dynamic Lifecycle. This is no-op.")
	return fmt.Errorf("lifecycle managed by Dynamic Lifecycle")
}

func (l *Lifecycle) Stop(sl *slog.Logger, _ context.Context) error {
	sl.Error("Stop() should not be called, lifecycle managed by Dynamic Lifecycle. This is no-op.")
	return fmt.Errorf("lifecycle managed by Dynamic Lifecycle")
}

func (l *Lifecycle) PrintHooks(w io.Writer) {
	fmt.Fprintf(w, "Lifecycle managed by Dynamic Lifecycle. This is no-op.")
}

// WithDynamicLifecycle provides a wrapper over the cell.Lifecycle to register DynamicFeature
// It groups the cells by DynamicFeatureName, providing a DynamicLifecycle for each feature.
// The hooks are immutable after the hive is initialized and are stored in a stateDB table, see table.go.
func WithDynamicLifecycle(feature DynamicFeatureName, deps []DynamicFeatureName, cells ...cell.Cell) cell.Cell {
	lc := &Lifecycle{}
	return cell.Group(
		cell.Provide(
			func() featureRegistrationOut {
				return featureRegistrationOut{FeatureRegistration: featureRegistration{Name: feature, Deps: deps, Lifecycle: lc}}
			},
		),
		cell.Decorate(
			func() cell.Lifecycle {
				return lc
			},
			cells...,
		),
	)
}
