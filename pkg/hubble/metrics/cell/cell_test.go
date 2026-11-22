// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

// Uses the real flag splitting and plugin registry, which calling
// ParseStaticMetricsConfig directly would skip.
func TestParseStaticMetricsConfig(t *testing.T) {
	t.Run("whitespace inside a template is rejected", func(t *testing.T) {
		cfg, err := parseStaticMetricsConfig("dns http:sourceContext=pod;path=/api/v1/users/{id}|/a b/c;onMiss.action=emit")
		require.ErrorContains(t, err, `invalid hubble-metrics: hubble-metrics entry "b/c;onMiss.action=emit" follows`)
		assert.Nil(t, cfg)
	})

	t.Run("valid config is parsed", func(t *testing.T) {
		cfg, err := parseStaticMetricsConfig("dns\n  httpV2:sourceContext=pod;path=/api/v1/users/{id};onMiss.action=drop_sample")
		require.NoError(t, err)
		require.Len(t, cfg.Metrics, 2)
		assert.Equal(t, &api.PathContext{
			Templates: []string{"/api/v1/users/{id}"},
			OnMiss:    api.OnMissPolicy{Action: api.OnMissDropSample},
		}, cfg.Metrics[1].PathContext)
	})

	t.Run("unknown metric without path settings still parses", func(t *testing.T) {
		cfg, err := parseStaticMetricsConfig("dns nosuchmetric")
		require.NoError(t, err)
		assert.Len(t, cfg.Metrics, 2)
	})
}
