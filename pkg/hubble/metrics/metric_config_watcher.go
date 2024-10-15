// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var metricReloadInterval = 10 * time.Second

type metricConfigWatcher struct {
	logger         logrus.FieldLogger
	configFilePath string
	callback       func(ctx context.Context, isSameHash bool, hash uint64, config api.Config)
	ticker         *time.Ticker
	stop           chan bool
	currentCfgHash uint64
}

// NewmetricConfigWatcher creates a config watcher instance. Config watcher notifies
// DynamicFlowProcessor when config file changes and dynamic metric config should be
// reconciled.
func NewMetricConfigWatcher(
	configFilePath string,
	callback func(ctx context.Context, isSameHash bool, hash uint64, config api.Config),
) *metricConfigWatcher {
	watcher := &metricConfigWatcher{
		logger:         logrus.New().WithField(logfields.LogSubsys, "hubble").WithField("configFilePath", configFilePath),
		configFilePath: configFilePath,
		callback:       callback,
		currentCfgHash: 0,
	}

	// initial configuration load
	watcher.reload()

	watcher.ticker = time.NewTicker(metricReloadInterval)
	watcher.stop = make(chan bool)

	go func() {
		for {
			select {
			case <-watcher.stop:
				return
			case <-watcher.ticker.C:
				watcher.reload()
			}
		}
	}()

	return watcher
}

func (c *metricConfigWatcher) reload() {
	c.logger.Debug("Attempting reload")
	config, isSameHash, hash, err := c.readConfig()
	if err != nil {
		c.logger.WithError(err).Warn("failed reading dynamic exporter config")
	} else {
		c.callback(context.TODO(), isSameHash, hash, *config)
	}
}

// Stop stops watcher.
func (c *metricConfigWatcher) Stop() {
	if c.ticker != nil {
		c.ticker.Stop()
	}
	c.stop <- true
}

func (c *metricConfigWatcher) readConfig() (*api.Config, bool, uint64, error) {
	config := &api.Config{Metrics: []*api.MetricConfig{}}
	yamlFile, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return nil, false, 0, fmt.Errorf("cannot read file '%s': %w", c.configFilePath, err)
	}
	if err := yaml.Unmarshal(yamlFile, config); err != nil {
		return nil, false, 0, fmt.Errorf("cannot parse yaml: %w", err)
	}

	if err := validateMetricConfig(config); err != nil {
		return nil, false, 0, fmt.Errorf("invalid yaml config file: %w", err)
	}

	newHash := calculateMetricHash(yamlFile)
	isSameHash := newHash == c.currentCfgHash
	c.currentCfgHash = newHash

	return config, isSameHash, newHash, nil
}

func calculateMetricHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}

func validateMetricConfig(config *api.Config) error {
	return nil
}
