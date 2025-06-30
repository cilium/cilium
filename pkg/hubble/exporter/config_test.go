// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestCompareFlowLogConfigs(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Minute)

	cases := []struct {
		name          string
		currentConfig *FlowLogConfig
		newConfig     *FlowLogConfig
		expectEqual   bool
	}{
		{
			name:          "should equal for same path",
			currentConfig: &FlowLogConfig{FilePath: "path"},
			newConfig:     &FlowLogConfig{FilePath: "path"},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different path",
			currentConfig: &FlowLogConfig{FilePath: "path"},
			newConfig:     &FlowLogConfig{FilePath: "other"},
			expectEqual:   false,
		},
		{
			name:          "should equal for same end date",
			currentConfig: &FlowLogConfig{End: &now},
			newConfig:     &FlowLogConfig{End: &now},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different end date",
			currentConfig: &FlowLogConfig{End: &now},
			newConfig:     &FlowLogConfig{End: &future},
			expectEqual:   false,
		},
		{
			name:          "should equal for same fieldmask",
			currentConfig: &FlowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &FlowLogConfig{FieldMask: []string{"a", "b"}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same fieldmask in different order",
			currentConfig: &FlowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &FlowLogConfig{FieldMask: []string{"b", "a"}},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different fieldmask",
			currentConfig: &FlowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &FlowLogConfig{FieldMask: []string{"c", "b"}},
			expectEqual:   false,
		},
		{
			name: "should equal for same include filters in different order",
			currentConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should not equal for different include filters",
			currentConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"kube-system/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name: "should equal for same exclude filters in different order",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should not equal for different exclude filters",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					SourcePod: []string{"kube-system/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name:        "should equal for null current config and null new config",
			expectEqual: true,
		},
		{
			name:        "should not equal for null current config and not null new config",
			newConfig:   &FlowLogConfig{},
			expectEqual: false,
		},
		{
			name:          "should not equal for not null current config and null new config",
			currentConfig: &FlowLogConfig{},
			expectEqual:   false,
		},
		{
			name: "should not equal when current filters are nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
				nil,
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name: "should not equal when new filters are nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
			}},
			expectEqual: false,
		},
		{
			name: "should equal when current and new filters are nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
			}},
			expectEqual: true,
		},
		{
			name: "should equal when current and new filters have nils",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				nil,
			}},
			expectEqual: true,
		},
		{
			name: "should equal when nil is substituted by empty instance",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{nil},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{{}},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should equal when empty instance is substituted by nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{{}},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{nil},
				},
			}},
			expectEqual: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentConfig.equals(tc.newConfig)
			assert.Equal(t, tc.expectEqual, result)
		})
	}
}

func TestYamlConfigFileUnmarshalling(t *testing.T) {
	// given
	filepath := "testdata/valid-flowlogs-config.yaml"
	configParser := &exporterConfigParser{}

	// when
	content, err := os.ReadFile(filepath)
	assert.NoError(t, err)
	configs, err := configParser.Parse(bytes.NewReader(content))
	assert.NoError(t, err)

	// then
	assert.Len(t, configs, 3)

	expectedDate := time.Date(2023, 10, 9, 23, 59, 59, 0, time.FixedZone("", -7*60*60))

	expectedConfigs := []FlowLogConfig{
		{
			Name:           "test001",
			FilePath:       "/var/log/network/flow-log/pa/test001.log",
			FieldMask:      FieldMask{},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &expectedDate,
		},
		{
			Name:      "test002",
			FilePath:  "/var/log/network/flow-log/pa/test002.log",
			FieldMask: FieldMask{"source.namespace", "source.pod_name", "destination.namespace", "destination.pod_name", "verdict"},
			IncludeFilters: FlowFilters{
				{
					SourcePod:   []string{"default/"},
					SourceLabel: []string{"networking.example.com/flow-logs=enabled"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			},
			ExcludeFilters: FlowFilters{},
			FileMaxSizeMB:  10,
			FileMaxBackups: 3,
			FileCompress:   true,
			End:            &expectedDate,
		},
		{
			Name:           "test003",
			FilePath:       "/var/log/network/flow-log/pa/test003.log",
			FieldMask:      FieldMask{"source", "destination", "verdict"},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"ingress/"},
				},
			},
			FileMaxSizeMB:  10,
			FileMaxBackups: 3,
			FileCompress:   true,
			End:            nil,
		},
	}

	for _, expected := range expectedConfigs {
		config, ok := configs[expected.Name].(*FlowLogConfig)
		assert.True(t, ok, "parsed config should be of type FlowLogConfig")
		testutils.AssertProtoEqual(t, &expected, config)
	}
}

func TestEmptyYamlConfigFileUnmarshalling(t *testing.T) {
	// given
	filepath := "testdata/empty-flowlogs-config.yaml"
	configParser := &exporterConfigParser{}

	// when
	content, err := os.ReadFile(filepath)
	assert.NoError(t, err)
	configs, err := configParser.Parse(bytes.NewReader(content))
	assert.NoError(t, err)

	// then
	assert.Empty(t, configs)
}

func TestInvalidConfigFile(t *testing.T) {
	cases := []struct {
		name             string
		filepath         string
		expectedErrorMsg string
	}{
		{
			name:             "missing file",
			filepath:         "non-existing-file-name",
			expectedErrorMsg: "no such file or directory",
		},
		{
			name:             "invalid yaml",
			filepath:         "testdata/invalid-flowlogs-config.yaml",
			expectedErrorMsg: "failed to unmarshal yaml config",
		},
		{
			name:             "duplicated name",
			filepath:         "testdata/duplicate-names-flowlogs-config.yaml",
			expectedErrorMsg: "duplicated flowlog name test001",
		},
		{
			name:             "duplicated path",
			filepath:         "testdata/duplicate-paths-flowlogs-config.yaml",
			expectedErrorMsg: "duplicated flowlog path /var/log/network/flow-log/pa/test001.log",
		},
	}

	configParser := &exporterConfigParser{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content, err := os.ReadFile(tc.filepath)
			if err != nil {
				assert.Contains(t, err.Error(), tc.expectedErrorMsg)
				return
			}
			configs, err := configParser.Parse(bytes.NewReader(content))
			assert.Empty(t, configs)
			assert.Contains(t, err.Error(), tc.expectedErrorMsg)
		})
	}
}

func TestFlowLogConfigEnd(t *testing.T) {
	exporterFactory := &exporterFactory{hivetest.Logger(t)}

	past = time.Now().Add(-1 * time.Hour)
	future = time.Now().Add(1 * time.Hour)

	tests := []struct {
		name    string
		config  *FlowLogConfig
		enabled bool
	}{
		{
			name:    "End nil means exporter enabled",
			config:  &FlowLogConfig{Name: "test001", FilePath: createEmptyLogFile(t).Name()},
			enabled: true,
		},
		{
			name:    "End future means exporter enabled",
			config:  &FlowLogConfig{Name: "test002", FilePath: createEmptyLogFile(t).Name(), End: &future},
			enabled: true,
		},
		{
			name:    "End past means exporter disabled",
			config:  &FlowLogConfig{Name: "test003", FilePath: createEmptyLogFile(t).Name(), End: &past},
			enabled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exporter, err := exporterFactory.Create(tc.config)
			assert.NoError(t, err)
			err = exporter.Export(t.Context(), &v1.Event{Event: &flow.Flow{Uuid: "1234"}})
			assert.NoError(t, err)
			content, err := os.ReadFile(tc.config.FilePath)
			assert.NoError(t, err)
			if tc.enabled {
				assert.NotEmpty(t, content)
			} else {
				assert.Empty(t, content)
			}
		})
	}
}

func createEmptyLogFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "output.log")
	if err != nil {
		t.Fatalf("failed creating test file %v", err)
	}
	return file
}
