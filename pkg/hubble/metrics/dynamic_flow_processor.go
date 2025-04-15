// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"errors"
	"log/slog"
	"reflect"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// DynamicFlowProcessor represents instance of hubble exporter with dynamic
// configuration reload.
type DynamicFlowProcessor struct {
	logger  *slog.Logger
	watcher *metricConfigWatcher
	// Protects against deregistering metric handlers while ProcessFlow is executing, or concurrent config reloads.
	mutex    lock.RWMutex
	Metrics  []api.NamedHandler
	registry *prometheus.Registry
}

// OnDecodedEvent distributes events across all managed exporters.
func (d *DynamicFlowProcessor) OnDecodedFlow(ctx context.Context, flow *flowpb.Flow) (bool, error) {
	select {
	case <-ctx.Done():
		return false, d.Stop()
	default:
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var errs error
	if d.Metrics != nil {
		for _, nh := range d.Metrics {
			// Continue running the remaining metrics handlers, since one failing
			// shouldn't impact the other metrics handlers.
			errs = errors.Join(errs, nh.Handler.ProcessFlow(ctx, flow))
		}
	}

	if errs != nil {
		d.logger.Error(
			"Failed to ProcessFlow in metrics handler",
			logfields.Error, errs,
		)
	}
	return false, errs
}

// Stop stops configuration watcher  and all deinitializes all metric handlers.
func (d *DynamicFlowProcessor) Stop() error {
	d.watcher.Stop()

	d.mutex.Lock()
	defer d.mutex.Unlock()

	var errs error
	for _, h := range d.Metrics {
		errs = errors.Join(errs, h.Handler.Deinit(d.registry))
	}

	return errs
}

// NewDynamicFlowProcessor creates instance of dynamic hubble flow exporter.
func NewDynamicFlowProcessor(reg *prometheus.Registry, logger *slog.Logger, configFilePath string) *DynamicFlowProcessor {
	dynamicFlowProcessor := &DynamicFlowProcessor{
		logger:   logger,
		registry: reg,
	}
	watcher := NewMetricConfigWatcher(logger, configFilePath, dynamicFlowProcessor.onConfigReload)
	dynamicFlowProcessor.watcher = watcher
	return dynamicFlowProcessor
}

func (d *DynamicFlowProcessor) onConfigReload(ctx context.Context, hash uint64, config api.Config) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var newHandlers []api.NamedHandler
	metricNames := config.GetMetricNames()

	curHandlerMap := make(map[string]*api.NamedHandler)
	if d.Metrics != nil {
		for _, m := range d.Metrics {
			curHandlerMap[m.Name] = &m
		}

		// Unregister handlers not present in the new config.
		// This needs to happen first to properly check for conflicting plugins later during registration.
		for _, m := range d.Metrics {
			if _, ok := metricNames[m.Name]; !ok {
				h := curHandlerMap[m.Name]
				err := h.Handler.Deinit(d.registry)
				if err != nil {
					d.logger.Error(
						"Deinit failed for handler",
						logfields.Error, err,
						logfields.Name, m.Name,
					)
				}
				delete(curHandlerMap, m.Name)
			}
		}
	}

	for _, cm := range config.Metrics {
		// Existing handler matches new config entry:
		//   no-op, if config unchanged;
		//   update handler config, if changed.
		if m, ok := curHandlerMap[cm.Name]; ok {
			if reflect.DeepEqual(*m.MetricConfig, *cm) {
				continue
			}
			err := m.Handler.HandleConfigurationUpdate(cm)
			if err != nil {
				d.logger.Error(
					"HandleConfigurationUpdate failed for handler",
					logfields.Error, err,
					logfields.Name, cm.Name,
				)
			}
			m.MetricConfig = cm
		} else {
			// New handler found in config.
			d.addNewMetric(d.registry, cm, metricNames, &newHandlers)
		}
	}

	for _, v := range curHandlerMap {
		newHandlers = append(newHandlers, *v)
	}

	d.Metrics = newHandlers
}

func (d *DynamicFlowProcessor) addNewMetric(reg *prometheus.Registry, cm *api.MetricConfig, metricNames map[string]*api.MetricConfig, newMetrics *[]api.NamedHandler) {
	nh, err := api.DefaultRegistry().ValidateAndCreateHandler(reg, cm, &metricNames)
	if err != nil {
		d.logger.Error(
			"Failed to configure metrics plugin",
			logfields.Error, err,
			logfields.Name, cm.Name,
		)

		return
	}

	err = api.InitHandler(d.logger, reg, nh)
	if err != nil {
		d.logger.Error(
			"Failed to configure metrics plugin",
			logfields.Error, err,
			logfields.Name, cm.Name,
		)

		return
	}
	*newMetrics = append(*newMetrics, *nh)
}
