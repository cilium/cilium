// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/time"
)

func TestReloadNotificationReceived(t *testing.T) {
	// given
	filepath := "testdata/valid-flowlogs-config.yaml"

	configReceived := false

	// when
	configParser := &exporterConfigParser{logrus.New()}
	watcher := NewConfigWatcher(filepath, configParser, func(configs map[string]ExporterConfig, hash uint64) {
		configReceived = true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go watcher.watch(ctx, 1*time.Millisecond)

	// then
	assert.Eventually(t, func() bool {
		return configReceived
	}, 1*time.Second, 1*time.Millisecond)
}
