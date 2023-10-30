// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// DynamicExporter represents instance of hubble exporter with dynamic
// configuration reload.
type DynamicExporter struct {
	FlowLogExporter
	logger           logrus.FieldLogger
	watcher          *configWatcher
	managedExporters map[string]*managedExporter
	maxFileSizeMB    int
	maxBackups       int
	// mutex protects from concurrent modification of managedExporters by config
	// reloader when hubble events are processed
	mutex lock.RWMutex
}

// OnDecodedEvent distributes events across all managed exporters.
func (d *DynamicExporter) OnDecodedEvent(ctx context.Context, event *v1.Event) (bool, error) {
	select {
	case <-ctx.Done():
		return false, d.Stop()
	default:
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var errs error
	for _, me := range d.managedExporters {
		if me.config.End == nil || me.config.End.After(time.Now()) {
			_, err := me.exporter.OnDecodedEvent(ctx, event)
			errs = errors.Join(errs, err)
		}
	}
	return false, errs
}

// Stop stops configuration watcher  and all managed flow log exporters.
func (d *DynamicExporter) Stop() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.watcher.Stop()

	var errs error
	for _, me := range d.managedExporters {
		errs = errors.Join(errs, me.exporter.Stop())
	}

	return errs
}

// NewDynamicExporter creates instance of dynamic hubble flow exporter.
func NewDynamicExporter(logger logrus.FieldLogger, configFilePath string, maxFileSizeMB, maxBackups int) *DynamicExporter {
	dynamicExporter := &DynamicExporter{
		logger:           logger,
		managedExporters: make(map[string]*managedExporter),
		maxFileSizeMB:    maxFileSizeMB,
		maxBackups:       maxBackups,
	}

	registerMetrics(dynamicExporter)

	watcher := NewConfigWatcher(configFilePath, dynamicExporter.onConfigReload)
	dynamicExporter.watcher = watcher
	return dynamicExporter
}

func (d *DynamicExporter) onConfigReload(ctx context.Context, hash uint64, config DynamicExportersConfig) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	configuredFlowLogNames := make(map[string]interface{})
	for _, flowlog := range config.FlowLogs {
		configuredFlowLogNames[flowlog.Name] = struct{}{}
		if _, ok := d.managedExporters[flowlog.Name]; ok {
			if d.applyUpdatedConfig(ctx, flowlog) {
				DynamicExporterReconfigurations.WithLabelValues("update").Inc()
			}
		} else {
			d.applyNewConfig(ctx, flowlog)
			DynamicExporterReconfigurations.WithLabelValues("add").Inc()
		}
	}

	for flowLogName := range d.managedExporters {
		if _, ok := configuredFlowLogNames[flowLogName]; !ok {
			d.applyRemovedConfig(flowLogName)
			DynamicExporterReconfigurations.WithLabelValues("remove").Inc()
		}
	}

	d.updateLastAppliedConfigGauges(hash)
}

func (d *DynamicExporter) applyNewConfig(ctx context.Context, flowlog *FlowLogConfig) {
	exporterOpts := []exporteroption.Option{
		exporteroption.WithPath(flowlog.FilePath),
		exporteroption.WithMaxSizeMB(d.maxFileSizeMB),
		exporteroption.WithMaxBackups(d.maxBackups),
		exporteroption.WithAllowList(flowlog.IncludeFilters),
		exporteroption.WithDenyList(flowlog.ExcludeFilters),
		exporteroption.WithFieldMask(flowlog.FieldMask),
	}

	exporter, err := NewExporter(ctx, d.logger.WithField("flowLogName", flowlog.Name), exporterOpts...)
	if err != nil {
		d.logger.Errorf("Failed to apply flowlog for name %s: %v", flowlog.Name, err)
	}

	d.managedExporters[flowlog.Name] = &managedExporter{
		config:   flowlog,
		exporter: exporter,
	}

}

func (d *DynamicExporter) applyUpdatedConfig(ctx context.Context, flowlog *FlowLogConfig) bool {
	m, ok := d.managedExporters[flowlog.Name]
	if ok && m.config.equals(flowlog) {
		return false
	}
	d.applyRemovedConfig(flowlog.Name)
	d.applyNewConfig(ctx, flowlog)
	return true
}

func (d *DynamicExporter) applyRemovedConfig(name string) {
	m, ok := d.managedExporters[name]
	if !ok {
		return
	}
	if err := m.exporter.Stop(); err != nil {
		d.logger.Errorf("failed to stop exporter: %v", err)
	}
	delete(d.managedExporters, name)
}

func (d *DynamicExporter) updateLastAppliedConfigGauges(hash uint64) {
	DynamicExporterConfigHash.WithLabelValues().Set(float64(hash))
	DynamicExporterConfigLastApplied.WithLabelValues().SetToCurrentTime()
}

type managedExporter struct {
	config   *FlowLogConfig
	exporter FlowLogExporter
}
