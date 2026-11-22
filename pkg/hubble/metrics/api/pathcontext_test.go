// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestParseStaticMetricsConfigPathContext(t *testing.T) {
	tests := []struct {
		name        string
		entry       string
		wantOptions []*ContextOptionConfig
		wantPath    *PathContext
	}{
		{
			name:        "no path options",
			entry:       "http:sourceContext=pod",
			wantOptions: []*ContextOptionConfig{{Name: "sourceContext", Values: ContextValues{"pod"}}},
		},
		{
			name:  "lifted out, other options kept in order",
			entry: "http:exemplars=true;path=/a/{id}|/b;sourceContext=pod;onMiss.action=drop_sample;onMiss.value=other",
			wantOptions: []*ContextOptionConfig{
				{Name: "exemplars", Values: ContextValues{"true"}},
				{Name: "sourceContext", Values: ContextValues{"pod"}},
			},
			wantPath: &PathContext{
				Templates: []string{"/a/{id}", "/b"},
				OnMiss:    OnMissPolicy{Action: OnMissDropSample, Value: "other"},
			},
		},
		{
			name:        "keys match case-insensitively",
			entry:       "http:PATH=/a;OnMiss.Action=emit;ONMISS.VALUE=x",
			wantOptions: []*ContextOptionConfig{},
			wantPath:    &PathContext{Templates: []string{"/a"}, OnMiss: OnMissPolicy{Action: OnMissEmit, Value: "x"}},
		},
		{
			// parseOptionValues would drop this.
			name:        "empty onMiss.value",
			entry:       "http:path=/a;onMiss.value=",
			wantOptions: []*ContextOptionConfig{},
			wantPath:    &PathContext{Templates: []string{"/a"}},
		},
		{
			name:        "onMiss.value keeps a pipe",
			entry:       "http:path=/a;onMiss.value=x|y",
			wantOptions: []*ContextOptionConfig{},
			wantPath:    &PathContext{Templates: []string{"/a"}, OnMiss: OnMissPolicy{Value: "x|y"}},
		},
		{
			name:        "stray pipe keeps the empty template",
			entry:       "http:path=/a||/b",
			wantOptions: []*ContextOptionConfig{},
			wantPath:    &PathContext{Templates: []string{"/a", "", "/b"}},
		},
		{
			name:        "bare path key",
			entry:       "http:path",
			wantOptions: []*ContextOptionConfig{},
			wantPath:    &PathContext{Templates: []string{""}},
		},
		{
			name:        "onMiss without path",
			entry:       "http:onMiss.action=emit",
			wantOptions: []*ContextOptionConfig{},
			wantPath:    &PathContext{OnMiss: OnMissPolicy{Action: OnMissEmit}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ParseStaticMetricsConfig([]string{tt.entry})
			require.Len(t, cfg.Metrics, 1)
			assert.Equal(t, tt.wantOptions, cfg.Metrics[0].ContextOptionConfigs)
			assert.Equal(t, tt.wantPath, cfg.Metrics[0].PathContext)
		})
	}
}

func TestCompilePathContext(t *testing.T) {
	tooMany := make([]string, 101)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("/r%d", i)
	}

	tests := []struct {
		name    string
		cfg     MetricConfig
		wantErr string
		wantNot string
		wantNil bool
	}{
		{
			name:    "unset",
			cfg:     MetricConfig{},
			wantNil: true,
		},
		{
			name: "valid with default onMiss",
			cfg:  MetricConfig{PathContext: &PathContext{Templates: []string{"/a/{id}"}}},
		},
		{
			name: "emit with a named bucket",
			cfg: MetricConfig{PathContext: &PathContext{
				Templates: []string{"/a/{id}"},
				OnMiss:    OnMissPolicy{Action: OnMissEmit, Value: "other"},
			}},
		},
		{
			name: "onMiss.value equal to a template under emit",
			cfg: MetricConfig{PathContext: &PathContext{
				Templates: []string{"/a", "/b"},
				OnMiss:    OnMissPolicy{Action: OnMissEmit, Value: "/b"},
			}},
			wantErr: `pathContext.onMiss.value "/b" is also a template`,
		},
		{
			name: "onMiss.value equal to a template under the default action",
			cfg: MetricConfig{PathContext: &PathContext{
				Templates: []string{"/a"},
				OnMiss:    OnMissPolicy{Value: "/a"},
			}},
			wantErr: `pathContext.onMiss.value "/a" is also a template`,
		},
		{
			name: "onMiss.value is ignored under drop_sample",
			cfg: MetricConfig{PathContext: &PathContext{
				Templates: []string{"/a"},
				OnMiss:    OnMissPolicy{Action: OnMissDropSample, Value: "/a"},
			}},
		},
		{
			name: "unknown onMiss.action",
			cfg: MetricConfig{PathContext: &PathContext{
				Templates: []string{"/a"},
				OnMiss:    OnMissPolicy{Action: "drop"},
			}},
			wantErr: `pathContext.onMiss.action "drop" is not one of "emit", "drop_sample"`,
		},
		{
			name:    "no templates",
			cfg:     MetricConfig{PathContext: &PathContext{}},
			wantErr: "pathContext.templates: no templates configured",
		},
		{
			name:    "malformed template",
			cfg:     MetricConfig{PathContext: &PathContext{Templates: []string{"/b_{bucket}"}}},
			wantErr: "pathContext.templates: templates[0]",
		},
		{
			name:    "empty template",
			cfg:     MetricConfig{PathContext: &PathContext{Templates: []string{""}}},
			wantErr: "template is empty",
			wantNot: "is also a template",
		},
		{
			name:    "duplicate template",
			cfg:     MetricConfig{PathContext: &PathContext{Templates: []string{"/a/{id}", "/a/{name}"}}},
			wantErr: "matches the same paths as templates[0]",
		},
		{
			name:    "over the template cap",
			cfg:     MetricConfig{PathContext: &PathContext{Templates: tooMany}},
			wantErr: "101 templates configured, at most 100 are supported",
		},
		{
			name: "path written into dynamic contextOptions",
			cfg: MetricConfig{ContextOptionConfigs: []*ContextOptionConfig{
				{Name: "path", Values: ContextValues{"/a"}},
			}},
			wantErr: `option "path" is not a context option, set it under pathContext`,
		},
		{
			name: "onMiss written into dynamic contextOptions next to pathContext",
			cfg: MetricConfig{
				ContextOptionConfigs: []*ContextOptionConfig{{Name: "onMiss.action", Values: ContextValues{"emit"}}},
				PathContext:          &PathContext{Templates: []string{"/a"}},
			},
			wantErr: `option "onMiss.action" is not a context option`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := tt.cfg.CompilePathContext()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, m)
				if tt.wantNot != "" {
					assert.NotContains(t, err.Error(), tt.wantNot)
				}
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, m)
			} else {
				assert.NotNil(t, m)
			}
		})
	}
}

// The CFP's static and dynamic examples must yield the same config. Static
// templates cannot contain ";", "|" or whitespace, so only that subset is covered.
func TestPathContextStaticDynamicParity(t *testing.T) {
	static := ParseStaticMetricsConfig(strings.Fields(
		"http:sourceContext=pod;destinationContext=pod;path=/api/v1/users/{id}|/api/v1/users/{id}/orders;onMiss.action=emit;onMiss.value=",
	))

	var dynamic Config
	require.NoError(t, yaml.Unmarshal([]byte(`
metrics:
- name: http
  contextOptions:
    - name: sourceContext
      values: [pod]
    - name: destinationContext
      values: [pod]
  pathContext:
    templates:
      - /api/v1/users/{id}
      - /api/v1/users/{id}/orders
    onMiss:
      action: emit
      value: ""
`), &dynamic))

	require.Len(t, static.Metrics, 1)
	require.Len(t, dynamic.Metrics, 1)
	s, d := static.Metrics[0], dynamic.Metrics[0]
	assert.Equal(t, d.Name, s.Name)
	assert.Equal(t, d.ContextOptionConfigs, s.ContextOptionConfigs)
	require.NotNil(t, s.PathContext)
	assert.Equal(t, d.PathContext, s.PathContext)

	_, err := s.CompilePathContext()
	require.NoError(t, err)
}
