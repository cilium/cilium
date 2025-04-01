// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"

	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var metricReloadInterval = 10 * time.Second

type metricConfigWatcher struct {
	logger         logging.FieldLogger
	configFilePath string
	callback       func(ctx context.Context, hash uint64, config api.Config)
	ticker         *time.Ticker
	stop           chan bool
	currentCfgHash uint64
	cfgStore       map[string]*api.MetricConfig
	mutex          lock.RWMutex
}

// NewMetricConfigWatcher creates a config watcher instance. Config watcher notifies
// DynamicFlowProcessor when config file changes and dynamic metric config should be
// reconciled.
func NewMetricConfigWatcher(
	logger *slog.Logger,
	configFilePath string,
	callback func(ctx context.Context, hash uint64, config api.Config),
) *metricConfigWatcher {
	watcher := &metricConfigWatcher{
		logger: logger.With(
			logfields.LogSubsys, "hubble",
			logfields.ConfigFile, configFilePath,
		),
		configFilePath: configFilePath,
		callback:       callback,
		currentCfgHash: 0,
		cfgStore:       make(map[string]*api.MetricConfig),
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
		c.logger.Error("failed reading dynamic exporter config", slog.Any(logfields.Error, err))
	} else {
		if !isSameHash {
			c.callback(context.TODO(), hash, *config)
		}
	}
}

func (c *metricConfigWatcher) resetCfgPath(path string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.configFilePath = path
}

// Stop stops watcher.
func (c *metricConfigWatcher) Stop() {
	if c.ticker != nil {
		c.ticker.Stop()
	}
	close(c.stop)
}

func (c *metricConfigWatcher) readConfig() (*api.Config, bool, uint64, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	config := &api.Config{Metrics: []*api.MetricConfig{}}
	yamlFile, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return nil, false, 0, fmt.Errorf("cannot read file '%s': %w", c.configFilePath, err)
	}
	if err := yaml.Unmarshal(yamlFile, config); err != nil {
		return nil, false, 0, fmt.Errorf("cannot parse yaml: %w", err)
	}

	if err := c.validateMetricConfig(config); err != nil {
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

func (c *metricConfigWatcher) validateMetricConfig(config *api.Config) error {
	metrics := make(map[string]any)
	var errs error

	for i, newMetric := range config.Metrics {
		if newMetric.Name == "" {
			errs = errors.Join(errs, fmt.Errorf("metric config validation failed - missing metric name at: %d", i))
			continue
		}
		if _, ok := metrics[newMetric.Name]; ok {
			errs = errors.Join(errs, fmt.Errorf("metric config validation failed - duplicate metric specified: %v", newMetric.Name))
		}
		metrics[newMetric.Name] = struct{}{}
		if oldMetric, ok := c.cfgStore[newMetric.Name]; ok {
			if !reflect.DeepEqual(newMetric.ContextOptionConfigs, oldMetric.ContextOptionConfigs) {
				errs = errors.Join(errs, fmt.Errorf("metric config validation failed - label set cannot be changed without restarting Prometheus. metric: %v", newMetric.Name))
			}
		}
	}

	if errs == nil {
		for _, newMetric := range config.Metrics {
			c.cfgStore[newMetric.Name] = newMetric
		}
	}
	return errs
}
