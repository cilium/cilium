// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

var (
	future = time.Now().Add(1 * time.Hour)
	past   = time.Now().Add(-1 * time.Hour)
)

func TestDynamicExporterLifecycle(t *testing.T) {
	// given
	fileName := "testdata/valid-flowlogs-config.yaml"

	// when
	sut := NewDynamicExporter(logrus.New(), fileName, 5, 1)

	// then
	assert.Len(t, sut.managedExporters, 3)
	for _, v := range sut.managedExporters {
		exp := v.exporter.(*exporter)
		assert.NotNil(t, exp.writer, "each individual exporter should be configured (writer != nil)")
	}

	// and when
	assert.NoError(t, sut.Stop())

	// then
	assert.Len(t, sut.managedExporters, 3)
	for _, v := range sut.managedExporters {
		exp := v.exporter.(*exporter)
		assert.Nil(t, exp.writer, "each individual exporter should be stopped (writer == nil)")
	}
}

func TestAddNewExporter(t *testing.T) {
	// given
	sut := &DynamicExporter{
		logger:           logrus.New(),
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	file := createEmptyLogFile(t)

	// and
	config := DynamicExportersConfig{
		FlowLogs: []*FlowLogConfig{
			{
				Name:           "test001",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &future,
			},
		},
	}

	// when
	sut.onConfigReload(context.TODO(), 1, config)

	// then
	assert.Equal(t, 1, len(sut.managedExporters))
	assert.Equal(t, config.FlowLogs[0], sut.managedExporters["test001"].config)
	assert.NotNil(t, sut.managedExporters["test001"].exporter)
}

func TestConfigReloadChanges(t *testing.T) {
	// given
	sut := &DynamicExporter{
		logger:           logrus.New(),
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	file := createEmptyLogFile(t)

	// and
	config := DynamicExportersConfig{
		FlowLogs: []*FlowLogConfig{
			{
				Name:           "test001",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &future,
			},
		},
	}

	mockExporter := &mockExporter{}
	sut.managedExporters["test001"] = &managedExporter{
		config:   config.FlowLogs[0],
		exporter: mockExporter,
	}

	// when
	sut.onConfigReload(context.TODO(), 1, config)

	// then
	assert.False(t, mockExporter.stopped, "should not reload when not changed")

	// and when
	newConfig := DynamicExportersConfig{
		FlowLogs: []*FlowLogConfig{
			{
				Name:           "test001",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{"source"},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &future,
			},
		},
	}
	sut.onConfigReload(context.TODO(), 1, newConfig)

	// then
	assert.True(t, mockExporter.stopped, "should reload when changed")
}

func TestEventPropagation(t *testing.T) {
	// given
	sut := &DynamicExporter{
		logger:           logrus.New(),
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	file := createEmptyLogFile(t)

	// and
	future := time.Now().Add(1 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)
	config := DynamicExportersConfig{
		FlowLogs: []*FlowLogConfig{
			{
				Name:           "test001",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &future,
			},
			{
				Name:           "test002",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &future,
			},
			{
				Name:           "test003",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &past,
			},
			{
				Name:           "test004",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            nil,
			},
		},
	}

	mockExporter0 := &mockExporter{}
	mockExporter1 := &mockExporter{}
	mockExporter2 := &mockExporter{}
	mockExporter3 := &mockExporter{}
	sut.managedExporters["test001"] = &managedExporter{
		config:   config.FlowLogs[0],
		exporter: mockExporter0,
	}
	sut.managedExporters["test002"] = &managedExporter{
		config:   config.FlowLogs[1],
		exporter: mockExporter1,
	}
	sut.managedExporters["test003"] = &managedExporter{
		config:   config.FlowLogs[2],
		exporter: mockExporter2,
	}
	sut.managedExporters["test004"] = &managedExporter{
		config:   config.FlowLogs[3],
		exporter: mockExporter3,
	}

	// when
	sut.OnDecodedEvent(context.TODO(), &v1.Event{})

	// then
	assert.Equal(t, 1, mockExporter0.events)
	assert.Equal(t, 1, mockExporter1.events)
	assert.Equal(t, 0, mockExporter2.events)
	assert.Equal(t, 1, mockExporter3.events)
}

func TestExporterReconfigurationMetricsReporting(t *testing.T) {
	// given
	registry := prometheus.NewRegistry()
	DynamicExporterReconfigurations.Reset()
	registry.MustRegister(DynamicExporterReconfigurations)

	// and
	sut := &DynamicExporter{
		logger:           logrus.New(),
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	file := createEmptyLogFile(t)

	t.Run("should report flowlog added metric", func(t *testing.T) {
		// given
		config := DynamicExportersConfig{
			FlowLogs: []*FlowLogConfig{
				{
					Name:           "test001",
					FilePath:       file.Name(),
					FieldMask:      FieldMask{},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
					End:            &future,
				},
			},
		}

		// when
		sut.onConfigReload(context.TODO(), 1, config)

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
		config := DynamicExportersConfig{
			FlowLogs: []*FlowLogConfig{
				{
					Name:           "test001",
					FilePath:       file.Name(),
					FieldMask:      FieldMask{"source"},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
					End:            &future,
				},
			},
		}

		// when
		sut.onConfigReload(context.TODO(), 1, config)

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
		config4 := DynamicExportersConfig{
			FlowLogs: []*FlowLogConfig{
				{
					Name:           "test001",
					FilePath:       file.Name(),
					FieldMask:      FieldMask{"source"},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
					End:            &future,
				},
			},
		}

		// when
		sut.onConfigReload(context.TODO(), 1, config4)

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
		// given
		config := DynamicExportersConfig{
			FlowLogs: []*FlowLogConfig{},
		}

		// when
		sut.onConfigReload(context.TODO(), 1, config)

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
	sut := &DynamicExporter{
		logger:           logrus.New(),
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	file := createEmptyLogFile(t)

	// given
	config := DynamicExportersConfig{
		FlowLogs: []*FlowLogConfig{
			{
				Name:           "test001",
				FilePath:       file.Name(),
				FieldMask:      FieldMask{},
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
				End:            &future,
			},
		},
	}

	//and
	configHash := uint64(4367168)

	// when
	sut.onConfigReload(context.TODO(), configHash, config)

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
	sut := &DynamicExporter{
		logger:           logrus.New(),
		managedExporters: make(map[string]*managedExporter),
	}

	// and
	registry := prometheus.NewRegistry()
	registry.MustRegister(&dynamicExporterGaugeCollector{exporter: sut})

	// and
	file := createEmptyLogFile(t)

	t.Run("should report gauge with exporters statuses", func(t *testing.T) {
		// given
		config := DynamicExportersConfig{
			FlowLogs: []*FlowLogConfig{
				{
					Name:           "test001",
					FilePath:       file.Name(),
					FieldMask:      FieldMask{},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
					End:            &future,
				},
				{
					Name:           "test002",
					FilePath:       file.Name(),
					FieldMask:      FieldMask{},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
					End:            &past,
				},
			},
		}

		// when
		sut.onConfigReload(context.TODO(), 1, config)

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
		// given
		config := DynamicExportersConfig{
			FlowLogs: []*FlowLogConfig{},
		}

		// when
		sut.onConfigReload(context.TODO(), 1, config)

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

func createEmptyLogFile(t *testing.T) *os.File {
	file, err := os.CreateTemp(t.TempDir(), "output.log")
	if err != nil {
		t.Fatalf("failed creating test file %v", err)
	}

	return file
}

type mockExporter struct {
	events  int
	stopped bool
}

func (m *mockExporter) Stop() error {
	m.stopped = true
	return nil
}

func (m *mockExporter) OnDecodedEvent(_ context.Context, _ *v1.Event) (bool, error) {
	m.events++
	return false, nil
}
