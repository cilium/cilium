// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/time"
)

func TestReloadNotificationReceived(t *testing.T) {
	// given
	filepath := "testdata/valid-flowlogs-config.yaml"

	configReceived := false

	// when
	configParser := &exporterConfigParser{hivetest.Logger(t)}
	watcher := NewConfigWatcher(hivetest.Logger(t), filepath, configParser, func(configs map[string]ExporterConfig, hash uint64) {
		configReceived = true
	})

	go watcher.watch(t.Context(), 1*time.Millisecond)

	// then
	assert.Eventually(t, func() bool {
		return configReceived
	}, 1*time.Second, 1*time.Millisecond)
}
