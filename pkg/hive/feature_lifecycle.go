// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/lock"
)

type FeatureLifecycleInterface interface {
	Append(Feature, cell.Hook) error
	Start(Feature, context.Context, *slog.Logger) error
	Stop(Feature, context.Context, *slog.Logger) error

	IsRunning(Feature) bool
	List() []Feature
}

type Feature string
type FeatureLifecycle struct {
	mu     lock.Mutex
	hooks  map[Feature][]cell.Hook
	status map[Feature]bool
}

func NewFeatureLifecycle() *FeatureLifecycle {
	return &FeatureLifecycle{
		hooks:  make(map[Feature][]cell.Hook),
		status: make(map[Feature]bool),
	}
}

// Append adds a hook to the feature hooks, marking the feature as not running.
// It returns an error if the feature is already running.
func (fl *FeatureLifecycle) Append(f Feature, h cell.Hook) error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if status, ok := fl.status[f]; ok && status {
		return fmt.Errorf("cannot add hooks to a running feature: %s", f)
	}

	fl.hooks[f] = append(fl.hooks[f], h)
	fl.status[f] = false

	return nil
}

// Start attempts to start a feature by executing its associated hooks.
// It returns an error if the feature is already running
// or if any hook fails to start.
func (fl *FeatureLifecycle) Start(f Feature, c context.Context, l *slog.Logger) error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if status, ok := fl.status[f]; ok && status {
		return fmt.Errorf("feature %s is already running", f)
	}

	l.Debug("Starting hooks for", "feature", f)
	for _, hook := range fl.hooks[f] {
		if err := hook.Start(c); err != nil {
			l.Error("Start hook failed", "error", err)
			return fmt.Errorf("starting hook for feature %s: %w", f, err)
		}
	}

	fl.status[f] = true

	return nil
}

// Stop attempts to stop a feature by stopping its associated hooks.
// It returns an error if the feature is already stopped.
// If any hook encounters an error during stopping it aggregates into return error
func (fl *FeatureLifecycle) Stop(f Feature, c context.Context, l *slog.Logger) error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if status, ok := fl.status[f]; ok && !status {
		return fmt.Errorf("feature %s is already stopped", f)
	}

	var errs error

	l.Debug("Stopping hooks for", "feature", f)

	for i := len(fl.hooks[f]) - 1; i >= 0; i-- {
		hook := fl.hooks[f][i]
		if err := hook.Stop(c); err != nil {
			l.Error("Stop hook failed", "error", err)
			errs = errors.Join(errs, err)
		}
	}

	fl.status[f] = false

	return errs
}

// IsRunning checks if a feature is currently running.
// It returns true if the feature exists in status map
// and its status is true, and false otherwise.
func (fl *FeatureLifecycle) IsRunning(f Feature) bool {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	status, ok := fl.status[f]
	return ok && status

}

// List returns a list of all features registered
func (fl *FeatureLifecycle) List() []Feature {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	return slices.Collect(maps.Keys(fl.hooks))
}
