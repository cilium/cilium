// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package promdump

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorGatherer struct {
	err error
}

func (g errorGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, g.err
}

func TestDumpGatherer(t *testing.T) {
	t.Run("nil constructor", func(t *testing.T) {
		err := DumpGatherer("cilium-agent", t.TempDir(), "feature-metrics.prom", nil)
		require.Error(t, err)
	})

	t.Run("empty output suffix", func(t *testing.T) {
		err := DumpGatherer("cilium-agent", t.TempDir(), "", func() (prometheus.Gatherer, error) {
			return prometheus.NewRegistry(), nil
		})
		require.Error(t, err)
	})

	t.Run("constructor error", func(t *testing.T) {
		wantErr := errors.New("boom")
		err := DumpGatherer("cilium-agent", t.TempDir(), "feature-metrics.prom", func() (prometheus.Gatherer, error) {
			return nil, wantErr
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, wantErr)
	})

	t.Run("nil gatherer", func(t *testing.T) {
		err := DumpGatherer("cilium-agent", t.TempDir(), "feature-metrics.prom", func() (prometheus.Gatherer, error) {
			return nil, nil
		})
		require.Error(t, err)
	})

	t.Run("gather failure", func(t *testing.T) {
		wantErr := errors.New("gather failed")
		err := DumpGatherer("cilium-agent", t.TempDir(), "feature-metrics.prom", func() (prometheus.Gatherer, error) {
			return errorGatherer{err: wantErr}, nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, wantErr)
	})

	t.Run("bad output directory", func(t *testing.T) {
		outputDir := filepath.Join(t.TempDir(), "does-not-exist")
		err := DumpGatherer("cilium-agent", outputDir, "feature-metrics.prom", func() (prometheus.Gatherer, error) {
			return prometheus.NewRegistry(), nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("app name creates missing subdirectory", func(t *testing.T) {
		err := DumpGatherer("bad/name", t.TempDir(), "feature-metrics.prom", func() (prometheus.Gatherer, error) {
			return prometheus.NewRegistry(), nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("output suffix creates missing subdirectory", func(t *testing.T) {
		err := DumpGatherer("cilium-agent", t.TempDir(), "bad/name.prom", func() (prometheus.Gatherer, error) {
			return prometheus.NewRegistry(), nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("success writes sorted metrics", func(t *testing.T) {
		outputDir := t.TempDir()
		reg := prometheus.NewRegistry()

		a := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "a_metric",
			Help: "a",
		})
		z := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "z_metric",
			Help: "z",
		})
		a.Set(1)
		z.Set(2)
		require.NoError(t, reg.Register(z))
		require.NoError(t, reg.Register(a))

		err := DumpGatherer("cilium-agent", outputDir, "feature-metrics.prom", func() (prometheus.Gatherer, error) {
			return reg, nil
		})
		require.NoError(t, err)

		outputFile := filepath.Join(outputDir, "cilium-agent.feature-metrics.prom")
		raw, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		text := string(raw)
		assert.Contains(t, text, "a_metric")
		assert.Contains(t, text, "z_metric")
		assert.Less(t, strings.Index(text, "a_metric"), strings.Index(text, "z_metric"))
	})
}
