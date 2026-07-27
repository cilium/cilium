// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/time"
)

var (
	future = time.Now().Add(1 * time.Hour)
	past   = time.Now().Add(-1 * time.Hour)
)

func TestDynamicExporterLifecycle(t *testing.T) {
	// given
	fileName := "testdata/valid-flowlogs-config.yaml"

	// when
	logger := hivetest.Logger(t)
	exporterFactory := &exporterFactory{logger}
	exporterConfigParser := &exporterConfigParser{logger}
	dynamicExporter := NewDynamicExporter(logger, fileName, exporterFactory, exporterConfigParser)

	// then
	assert.Len(t, dynamicExporter.managedExporters, 3)
	for _, v := range dynamicExporter.managedExporters {
		exp := v.exporter.(*exporter)
		assert.NotNil(t, exp.writer, "each individual exporter should be configured (writer != nil)")
	}

	// and when
	assert.NoError(t, dynamicExporter.Stop())

	// then
	assert.Len(t, dynamicExporter.managedExporters, 3)
	for _, v := range dynamicExporter.managedExporters {
		exp := v.exporter.(*exporter)
		assert.Nil(t, exp.writer, "each individual exporter should be stopped (writer == nil)")
	}
}

func TestAddNewExporter(t *testing.T) {
	// given
	logger := hivetest.Logger(t)
	exporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	config := &FlowLogConfig{
		Name:           "test001",
		FilePath:       "test.log",
		FieldMask:      FieldMask{},
		IncludeFilters: FlowFilters{},
		ExcludeFilters: FlowFilters{},
		End:            &future,
	}

	// when
	exporter.onConfigReload(map[string]ExporterConfig{"test001": config}, 1)

	// then
	assert.Len(t, exporter.managedExporters, 1)
	gotConfig, ok := exporter.managedExporters["test001"].config.(*FlowLogConfig)
	assert.True(t, ok, "managed config should be of type FlowLogConfig")
	assert.Equal(t, config, gotConfig)
	assert.NotNil(t, exporter.managedExporters["test001"].exporter)
}

func TestConfigReloadChanges(t *testing.T) {
	// given
	logger := hivetest.Logger(t)
	exporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	config := &FlowLogConfig{
		Name:           "test001",
		FilePath:       "test.log",
		FieldMask:      FieldMask{},
		IncludeFilters: FlowFilters{},
		ExcludeFilters: FlowFilters{},
		End:            &future,
	}

	mockExporter := &mockExporter{}
	exporter.managedExporters["test001"] = &managedExporter{
		config:   config,
		exporter: mockExporter,
	}

	// when
	exporter.onConfigReload(map[string]ExporterConfig{"test001": config}, 1)

	// then
	assert.False(t, mockExporter.stopped, "should not reload when not changed")

	// and when
	newConfig := &FlowLogConfig{
		Name:           "test001",
		FilePath:       "test.log",
		FieldMask:      FieldMask{"source"},
		IncludeFilters: FlowFilters{},
		ExcludeFilters: FlowFilters{},
		End:            &future,
	}
	exporter.onConfigReload(map[string]ExporterConfig{"test001": newConfig}, 1)

	// then
	assert.True(t, mockExporter.stopped, "should reload when changed")
}

func TestEventPropagation(t *testing.T) {
	// given
	exporter := &dynamicExporter{
		logger:           hivetest.Logger(t),
		managedExporters: make(map[string]*managedExporter),
	}

	mockExporter0 := &mockExporter{}
	mockExporter1 := &mockExporter{}
	mockExporter2 := &mockExporter{}
	exporter.managedExporters["test001"] = &managedExporter{
		config:   &FlowLogConfig{Name: "test001"},
		exporter: mockExporter0,
	}
	exporter.managedExporters["test002"] = &managedExporter{
		config:   &FlowLogConfig{Name: "test002"},
		exporter: mockExporter1,
	}
	exporter.managedExporters["test003"] = &managedExporter{
		config:   &FlowLogConfig{Name: "test003"},
		exporter: mockExporter2,
	}

	// when
	exporter.Export(t.Context(), &v1.Event{})

	// then
	assert.Equal(t, 1, mockExporter0.events)
	assert.Equal(t, 1, mockExporter1.events)
	assert.Equal(t, 1, mockExporter2.events)
}

func TestExporterReconfigurationMetricsReporting(t *testing.T) {
	// given
	registry := prometheus.NewRegistry()
	DynamicExporterReconfigurations.Reset()
	registry.MustRegister(DynamicExporterReconfigurations)

	// and
	logger := hivetest.Logger(t)
	exporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	t.Run("should report flowlog added metric", func(t *testing.T) {
		// given
		config := &FlowLogConfig{
			Name:           "test001",
			FilePath:       "test.log",
			FieldMask:      FieldMask{},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &future,
		}

		// when
		exporter.onConfigReload(map[string]ExporterConfig{"test001": config}, 1)

		// then
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_dynamic_exporter_reconfigurations_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 1)
		metric := metricFamilies[0].Metric[0]

		assert.Equal(t, "op", *metric.Label[0].Name)
		assert.Equal(t, "add", *metric.Label[0].Value)
		assert.Equal(t, float64(1), *metric.GetCounter().Value)
	})

	t.Run("should report flowlog updated metric", func(t *testing.T) {
		// given
		config := &FlowLogConfig{
			Name:           "test001",
			FilePath:       "test.log",
			FieldMask:      FieldMask{"source"},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &future,
		}

		// when
		exporter.onConfigReload(map[string]ExporterConfig{"test001": config}, 1)

		// then
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_dynamic_exporter_reconfigurations_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)
		metric := metricFamilies[0].Metric[1]

		assert.Equal(t, "op", *metric.Label[0].Name)
		assert.Equal(t, "update", *metric.Label[0].Value)
		assert.Equal(t, float64(1), *metric.GetCounter().Value)
	})

	t.Run("should not increase flowlog updated metric when config not changed", func(t *testing.T) {
		// given
		config := &FlowLogConfig{
			Name:           "test001",
			FilePath:       "test.log",
			FieldMask:      FieldMask{"source"},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &future,
		}

		// when
		exporter.onConfigReload(map[string]ExporterConfig{"test001": config}, 1)

		// then
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_dynamic_exporter_reconfigurations_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)
		metric := metricFamilies[0].Metric[1]

		assert.Equal(t, "op", *metric.Label[0].Name)
		assert.Equal(t, "update", *metric.Label[0].Value)
		assert.Equal(t, float64(1), *metric.GetCounter().Value)
	})

	t.Run("should report flowlog removed metric", func(t *testing.T) {
		// when
		exporter.onConfigReload(map[string]ExporterConfig{}, 1)

		// then
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_dynamic_exporter_reconfigurations_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 3)
		metric := metricFamilies[0].Metric[1]

		assert.Equal(t, "op", *metric.Label[0].Name)
		assert.Equal(t, "remove", *metric.Label[0].Value)
		assert.Equal(t, float64(1), *metric.GetCounter().Value)
	})
}

func TestExporterReconfigurationHashMetricsReporting(t *testing.T) {
	// given
	registry := prometheus.NewRegistry()
	DynamicExporterConfigHash.Reset()
	DynamicExporterConfigLastApplied.Reset()
	registry.MustRegister(DynamicExporterConfigHash, DynamicExporterConfigLastApplied)

	// and
	logger := hivetest.Logger(t)
	exporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	// given
	config := &FlowLogConfig{
		Name:           "test001",
		FilePath:       "test.log",
		FieldMask:      FieldMask{},
		IncludeFilters: FlowFilters{},
		ExcludeFilters: FlowFilters{},
		End:            &future,
	}

	// and
	configHash := uint64(4367168)

	// when
	exporter.onConfigReload(map[string]ExporterConfig{"test001": config}, configHash)

	// then
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 2)

	assert.Equal(t, "hubble_dynamic_exporter_config_hash", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, 1)
	hash := metricFamilies[0].Metric[0]

	assert.Equal(t, float64(configHash), *hash.GetGauge().Value)

	assert.Equal(t, "hubble_dynamic_exporter_config_last_applied", *metricFamilies[1].Name)
	require.Len(t, metricFamilies[1].Metric, 1)
	timestamp := metricFamilies[1].Metric[0]
	assert.InDelta(t, time.Now().Unix(), *timestamp.GetGauge().Value, 1, "verify reconfiguration within 1 second from now")
}

func TestExportersMetricsReporting(t *testing.T) {
	// given
	logger := hivetest.Logger(t)
	exporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	registry := prometheus.NewRegistry()
	registry.MustRegister(&dynamicExporterGaugeCollector{exporter: exporter})

	t.Run("should report gauge with exporters statuses", func(t *testing.T) {
		// given
		config1 := &FlowLogConfig{

			Name:           "test001",
			FilePath:       "test1.log",
			FieldMask:      FieldMask{},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &future,
		}
		config2 := &FlowLogConfig{
			Name:           "test002",
			FilePath:       "test2.log",
			FieldMask:      FieldMask{},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &past,
		}

		// when
		exporter.onConfigReload(map[string]ExporterConfig{"test001": config1, "test002": config2}, 1)

		// then
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 2)

		assert.Equal(t, "hubble_dynamic_exporter_exporters_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)

		assert.Equal(t, "status", *metricFamilies[0].Metric[0].Label[0].Name)
		assert.Equal(t, "active", *metricFamilies[0].Metric[0].Label[0].Value)
		assert.Equal(t, float64(1), *metricFamilies[0].Metric[0].GetGauge().Value)

		assert.Equal(t, "status", *metricFamilies[0].Metric[1].Label[0].Name)
		assert.Equal(t, "inactive", *metricFamilies[0].Metric[1].Label[0].Value)
		assert.Equal(t, float64(1), *metricFamilies[0].Metric[1].GetGauge().Value)

		assert.Equal(t, "hubble_dynamic_exporter_up", *metricFamilies[1].Name)
		require.Len(t, metricFamilies[1].Metric, 2)

		assert.Equal(t, "name", *metricFamilies[1].Metric[0].Label[0].Name)
		assert.Equal(t, "test001", *metricFamilies[1].Metric[0].Label[0].Value)
		assert.Equal(t, float64(1), *metricFamilies[1].Metric[0].GetGauge().Value)

		assert.Equal(t, "name", *metricFamilies[1].Metric[1].Label[0].Name)
		assert.Equal(t, "test002", *metricFamilies[1].Metric[1].Label[0].Value)
		assert.Equal(t, float64(0), *metricFamilies[1].Metric[1].GetGauge().Value)
	})

	t.Run("should remove individual status metric of removed flowlog", func(t *testing.T) {
		// when
		exporter.onConfigReload(map[string]ExporterConfig{}, 1)

		// then
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_dynamic_exporter_exporters_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)

		assert.Equal(t, "status", *metricFamilies[0].Metric[0].Label[0].Name)
		assert.Equal(t, "active", *metricFamilies[0].Metric[0].Label[0].Value)
		assert.Equal(t, float64(0), *metricFamilies[0].Metric[0].GetGauge().Value)

		assert.Equal(t, "status", *metricFamilies[0].Metric[1].Label[0].Name)
		assert.Equal(t, "inactive", *metricFamilies[0].Metric[1].Label[0].Value)
		assert.Equal(t, float64(0), *metricFamilies[0].Metric[1].GetGauge().Value)
	})
}

var _ FlowLogExporter = (*mockExporter)(nil)

type mockExporter struct {
	events  int
	stopped bool
}

func (m *mockExporter) Export(_ context.Context, _ *v1.Event) error {
	m.events++
	return nil
}

func (m *mockExporter) Stop() error {
	m.stopped = true
	return nil
}
