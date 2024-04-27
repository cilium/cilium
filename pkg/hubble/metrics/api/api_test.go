// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestDefaultRegistry(t *testing.T) {
	prometheusRegistry := prometheus.NewPedanticRegistry()
	registry := DefaultRegistry()

	assert.NotNil(t, registry)

	registry.ConfigureHandlers(prometheusRegistry, &DynamicMetricsConfig{
		[]*MetricConfig{
			{
				Name:           "drop",
				IncludeFilters: FlowFilters{},
				ExcludeFilters: FlowFilters{},
			},
		},
	},
	)
}

func TestParseMetricOptions(t *testing.T) {
	assert.EqualValues(t, ParseStaticMetricsConfig([]string{"a", "b"}),
		&DynamicMetricsConfig{
			[]*MetricConfig{
				{
					Name:                 "a",
					IncludeFilters:       FlowFilters{},
					ExcludeFilters:       FlowFilters{},
					ContextOptionConfigs: ContextOptionConfigs{},
				},
				{
					Name:                 "b",
					IncludeFilters:       FlowFilters{},
					ExcludeFilters:       FlowFilters{},
					ContextOptionConfigs: ContextOptionConfigs{},
				},
			},
		},
	)
	assert.EqualValues(t, ParseStaticMetricsConfig([]string{"a:1;2", "b"}),
		&DynamicMetricsConfig{
			[]*MetricConfig{
				{
					Name:           "a",
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
					ContextOptionConfigs: []*ContextOptionConfig{
						{
							Name:   "1",
							Values: []string{""},
						},
						{
							Name:   "2",
							Values: []string{""},
						},
					},
				},
				{
					Name:                 "b",
					IncludeFilters:       FlowFilters{},
					ExcludeFilters:       FlowFilters{},
					ContextOptionConfigs: ContextOptionConfigs{},
				},
			},
		},
	)
	assert.EqualValues(t, ParseStaticMetricsConfig([]string{"a:1;2", "b:3;4"}),
		&DynamicMetricsConfig{
			[]*MetricConfig{
				{
					Name: "a",
					ContextOptionConfigs: []*ContextOptionConfig{
						{
							Name:   "1",
							Values: []string{""},
						},
						{
							Name:   "2",
							Values: []string{""},
						},
					},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
				},
				{
					Name: "b",
					ContextOptionConfigs: []*ContextOptionConfig{
						{
							Name:   "3",
							Values: []string{""},
						},
						{
							Name:   "4",
							Values: []string{""},
						},
					},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
				},
			},
		},
	)
	assert.EqualValues(t, ParseStaticMetricsConfig([]string{"http:labelsContext=source_namespace,source_pod", "flow:destinationContext=dns|ip"}),
		&DynamicMetricsConfig{
			[]*MetricConfig{
				{
					Name: "http",
					ContextOptionConfigs: []*ContextOptionConfig{
						{
							Name:   "labelsContext",
							Values: []string{"source_namespace", "source_pod"},
						},
					},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
				},
				{
					Name: "flow",
					ContextOptionConfigs: []*ContextOptionConfig{
						{
							Name:   "destinationContext",
							Values: []string{"dns", "ip"},
						},
					},
					IncludeFilters: FlowFilters{},
					ExcludeFilters: FlowFilters{},
				},
			},
		},
	)
}
