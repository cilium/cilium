// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/time"
)

func TestYamlConfigFileUnmarshalling(t *testing.T) {
	// given
	fileName := "testdata/valid-flowlogs-config.yaml"

	sut := configWatcher{configFilePath: fileName}

	// when
	config, hash, err := sut.readConfig()
	assert.NoError(t, err)

	// then
	assert.Equal(t, 3, len(config.FlowLogs))

	assert.Equal(t, uint64(0x31b7b661343ab32f), hash)

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
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			},
			ExcludeFilters: FlowFilters{},
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
			End: nil,
		},
	}

	for i := range expectedConfigs {
		assertFlowLogConfig(t, expectedConfigs[i], *config.FlowLogs[i])
	}
}

func TestEmptyYamlConfigFileUnmarshalling(t *testing.T) {
	// given
	fileName := "testdata/empty-flowlogs-config.yaml"

	sut := configWatcher{configFilePath: fileName}

	// when
	config, hash, err := sut.readConfig()
	assert.NoError(t, err)

	// then
	assert.Equal(t, 0, len(config.FlowLogs))
	assert.Equal(t, uint64(0x4b2008fd98c1dd4), hash)
}

func TestInvalidConfigFile(t *testing.T) {
	cases := []struct {
		name             string
		watcher          *configWatcher
		expectedErrorMsg string
	}{
		{
			name:             "missing file",
			watcher:          &configWatcher{configFilePath: "non-existing-file-name"},
			expectedErrorMsg: "cannot read file",
		},
		{
			name:             "invalid yaml",
			watcher:          &configWatcher{configFilePath: "testdata/invalid-flowlogs-config.yaml"},
			expectedErrorMsg: "cannot parse yaml",
		},
		{
			name:             "duplicated name",
			watcher:          &configWatcher{configFilePath: "testdata/duplicate-names-flowlogs-config.yaml"},
			expectedErrorMsg: "invalid yaml config file duplicated flowlog name test001",
		},
		{
			name:             "duplicated path",
			watcher:          &configWatcher{configFilePath: "testdata/duplicate-paths-flowlogs-config.yaml"},
			expectedErrorMsg: "invalid yaml config file duplicated flowlog path /var/log/network/flow-log/pa/test001.log",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config, _, err := tc.watcher.readConfig()
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), tc.expectedErrorMsg)
		})
	}
}

func TestReloadNotificationReceived(t *testing.T) {
	// given
	fileName := "testdata/valid-flowlogs-config.yaml"

	configReceived := false

	// when
	reloadInterval = 1 * time.Millisecond
	sut := NewConfigWatcher(fileName, func(_ context.Context, _ uint64, config DynamicExportersConfig) {
		configReceived = true
	})
	defer sut.Stop()

	// then
	assert.Eventually(t, func() bool {
		return configReceived
	}, 1*time.Second, 1*time.Millisecond)

}

func assertFlowLogConfig(t *testing.T, expected, actual FlowLogConfig) {

	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.FilePath, actual.FilePath)
	assert.Equal(t, expected.FieldMask, actual.FieldMask)
	assert.Equal(t, len(expected.IncludeFilters), len(actual.IncludeFilters))
	for i := range expected.IncludeFilters {
		assert.Equal(t, expected.IncludeFilters[i].String(), actual.IncludeFilters[i].String())
	}
	assert.Equal(t, len(expected.ExcludeFilters), len(actual.ExcludeFilters))
	for i := range expected.ExcludeFilters {
		assert.Equal(t, expected.ExcludeFilters[i].String(), actual.ExcludeFilters[i].String())
	}
	if expected.End == nil {
		assert.Nil(t, actual.End)
	} else {
		assert.True(t, expected.End.Equal(*actual.End), "expected %s vs actual %s", expected.End.String(), actual.End.String())
	}

}
