// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"errors"
	"log/slog"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var reloadInterval = 5 * time.Second

// ExporterConfig is a configuration used by ExporterFactory.
type ExporterConfig interface {
	Equal(other any) bool
	IsActive() bool
}

// ExporterFactory is a factory for creating FlowLogExporter instances.
type ExporterFactory interface {
	Create(config ExporterConfig) (FlowLogExporter, error)
}

type managedExporter struct {
	config   ExporterConfig
	exporter FlowLogExporter
}

var _ FlowLogExporter = (*dynamicExporter)(nil)

// dynamicExporter is a wrapper of the hubble exporter that supports dynamic configuration reload
// for a set of exporters.
type dynamicExporter struct {
	logger          *slog.Logger
	watcher         *configWatcher
	exporterFactory ExporterFactory

	mu               lock.RWMutex
	managedExporters map[string]*managedExporter
}

// NewDynamicExporter initializes a dynamic exporter.
//
// NOTE: Stopped instances cannot be restarted and should be re-created.
func NewDynamicExporter(logger *slog.Logger, configFilePath string, exporterFactory ExporterFactory, exporterConfigParser ExporterConfigParser) *dynamicExporter {
	dynamicExporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  exporterFactory,
		managedExporters: make(map[string]*managedExporter),
	}
	watcher := NewConfigWatcher(logger, configFilePath, exporterConfigParser, func(configs map[string]ExporterConfig, hash uint64) {
		if err := dynamicExporter.onConfigReload(configs, hash); err != nil {
			logger.Error("Failed to reload exporter manager", logfields.Error, err)
		}
	})
	dynamicExporter.watcher = watcher

	registerMetrics(dynamicExporter)
	return dynamicExporter
}

// Watch starts watching the exporter configuration file at regular intervals and initiate a reload
// whenever the config changes. It blocks until the context is cancelled.
func (d *dynamicExporter) Watch(ctx context.Context) error {
	return d.watcher.watch(ctx, reloadInterval)
}

// Export implements FlowLogExporter.
//
// It distributes events across all managed exporters.
func (d *dynamicExporter) Export(ctx context.Context, ev *v1.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	var errs error
	for _, me := range d.managedExporters {
		errs = errors.Join(errs, me.exporter.Export(ctx, ev))
	}
	return errs
}

// Stop implements FlowLogExporter.
//
// It stops all managed flow log exporters.
func (d *dynamicExporter) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs error
	for _, me := range d.managedExporters {
		errs = errors.Join(errs, me.exporter.Stop())
	}
	return errs
}

func (d *dynamicExporter) onConfigReload(configs map[string]ExporterConfig, hash uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	configuredExporterNames := make(map[string]struct{})
	for name, config := range configs {
		configuredExporterNames[name] = struct{}{}
		var label string
		if _, ok := d.managedExporters[name]; ok {
			label = "update"
		} else {
			label = "add"
		}
		if d.applyUpdatedConfig(name, config) {
			DynamicExporterReconfigurations.WithLabelValues(label).Inc()
		}
	}

	for name := range d.managedExporters {
		if _, ok := configuredExporterNames[name]; !ok {
			if d.removeExporter(name) {
				DynamicExporterReconfigurations.WithLabelValues("remove").Inc()
			}
		}
	}

	DynamicExporterConfigHash.WithLabelValues().Set(float64(hash))
	DynamicExporterConfigLastApplied.WithLabelValues().SetToCurrentTime()

	return nil
}

// NOTE: mutex must be locked before calling this method.
func (d *dynamicExporter) applyUpdatedConfig(name string, config ExporterConfig) bool {
	me, ok := d.managedExporters[name]
	if ok && me.config.Equal(config) {
		return false
	}

	exporter, err := d.exporterFactory.Create(config)
	if err != nil {
		d.logger.Error("Failed to create exporter for config",
			logfields.Error, err,
			logfields.Name, name,
		)
		return false
	}

	d.removeExporter(name)
	d.managedExporters[name] = &managedExporter{
		config:   config,
		exporter: exporter,
	}
	return true
}

// NOTE: mutex must be locked before calling this method.
func (d *dynamicExporter) removeExporter(name string) bool {
	me, ok := d.managedExporters[name]
	if !ok {
		return false
	}
	if err := me.exporter.Stop(); err != nil {
		d.logger.Error("failed to stop exporter", logfields.Error, err)
	}
	delete(d.managedExporters, name)
	return true
}
