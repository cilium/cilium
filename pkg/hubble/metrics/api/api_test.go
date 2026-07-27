// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	pb "github.com/cilium/cilium/api/v1/flow"
)

func TestDefaultRegistry(t *testing.T) {
	prometheusRegistry := prometheus.NewPedanticRegistry()
	registry := DefaultRegistry()

	assert.NotNil(t, registry)

	registry.ConfigureHandlers(hivetest.Logger(t), prometheusRegistry, &Config{
		[]*MetricConfig{
			{
				Name:           "drop",
				IncludeFilters: []*pb.FlowFilter{},
				ExcludeFilters: []*pb.FlowFilter{},
			},
		},
	},
	)
}

func TestParseMetricOptions(t *testing.T) {
	assert.Equal(t, &Config{
		[]*MetricConfig{
			{
				Name:                 "a",
				IncludeFilters:       []*pb.FlowFilter{},
				ExcludeFilters:       []*pb.FlowFilter{},
				ContextOptionConfigs: []*ContextOptionConfig{},
			},
			{
				Name:                 "b",
				IncludeFilters:       []*pb.FlowFilter{},
				ExcludeFilters:       []*pb.FlowFilter{},
				ContextOptionConfigs: []*ContextOptionConfig{},
			},
		},
	}, ParseStaticMetricsConfig([]string{"a", "b"}),
	)
	assert.Equal(t, &Config{
		[]*MetricConfig{
			{
				Name:           "a",
				IncludeFilters: []*pb.FlowFilter{},
				ExcludeFilters: []*pb.FlowFilter{},
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
				IncludeFilters:       []*pb.FlowFilter{},
				ExcludeFilters:       []*pb.FlowFilter{},
				ContextOptionConfigs: []*ContextOptionConfig{},
			},
		},
	}, ParseStaticMetricsConfig([]string{"a:1;2", "b"}),
	)
	assert.Equal(t, &Config{
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
				IncludeFilters: []*pb.FlowFilter{},
				ExcludeFilters: []*pb.FlowFilter{},
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
				IncludeFilters: []*pb.FlowFilter{},
				ExcludeFilters: []*pb.FlowFilter{},
			},
		},
	}, ParseStaticMetricsConfig([]string{"a:1;2", "b:3;4"}),
	)
	assert.Equal(t, &Config{
		[]*MetricConfig{
			{
				Name: "http",
				ContextOptionConfigs: []*ContextOptionConfig{
					{
						Name:   "labelsContext",
						Values: []string{"source_namespace", "source_pod"},
					},
				},
				IncludeFilters: []*pb.FlowFilter{},
				ExcludeFilters: []*pb.FlowFilter{},
			},
			{
				Name: "flow",
				ContextOptionConfigs: []*ContextOptionConfig{
					{
						Name:   "destinationContext",
						Values: []string{"dns", "ip"},
					},
				},
				IncludeFilters: []*pb.FlowFilter{},
				ExcludeFilters: []*pb.FlowFilter{},
			},
		},
	}, ParseStaticMetricsConfig([]string{"http:labelsContext=source_namespace,source_pod", "flow:destinationContext=dns|ip"}),
	)
}
