// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// configWatcher provides dynamic configuration reload for DynamicExporter.
type configWatcher struct {
	logger         logrus.FieldLogger
	configFilePath string
	callback       func(hash uint64, config DynamicExportersConfig)
}

// NewConfigWatcher returns a new configWatcher that invokes callback when the provided config file
// changes.
func NewConfigWatcher(
	configFilePath string,
	callback func(hash uint64, config DynamicExportersConfig),
) *configWatcher {
	watcher := &configWatcher{
		logger:         logrus.New().WithField(logfields.LogSubsys, "hubble").WithField("configFilePath", configFilePath),
		configFilePath: configFilePath,
		callback:       callback,
	}

	// initial configuration load
	watcher.reload()
	return watcher
}

// watch starts the watcher and blocks until the context is cancelled.
func (c *configWatcher) watch(ctx context.Context, interval time.Duration) error {
	// TODO replace ticker reloads with inotify watchers
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.reload()
		}
	}
}

func (c *configWatcher) reload() {
	c.logger.Debug("Attempting reload")
	config, hash, err := c.readConfig()
	if err != nil {
		DynamicExporterReconfigurations.WithLabelValues("failure").Inc()
		c.logger.WithError(err).Warn("failed reading dynamic exporter config")
	} else {
		c.callback(hash, *config)
	}
}

func (c *configWatcher) readConfig() (*DynamicExportersConfig, uint64, error) {
	config := &DynamicExportersConfig{}
	yamlFile, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read file '%s': %w", c.configFilePath, err)
	}
	if err := yaml.Unmarshal(yamlFile, config); err != nil {
		return nil, 0, fmt.Errorf("cannot parse yaml: %w", err)
	}

	if err := validateConfig(config); err != nil {
		return nil, 0, fmt.Errorf("invalid yaml config file: %w", err)
	}

	return config, calculateHash(yamlFile), nil
}

func calculateHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}

func validateConfig(config *DynamicExportersConfig) error {
	flowlogNames := make(map[string]interface{})
	flowlogPaths := make(map[string]interface{})

	var errs error

	for i := range config.FlowLogs {
		if config.FlowLogs[i] == nil {
			errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d", i))
			continue
		}
		name := config.FlowLogs[i].Name
		if name == "" {
			errs = errors.Join(errs, fmt.Errorf("name is required"))
		} else {
			if _, ok := flowlogNames[name]; ok {
				errs = errors.Join(errs, fmt.Errorf("duplicated flowlog name %s", name))
			}
			flowlogNames[name] = struct{}{}
		}

		filePath := config.FlowLogs[i].FilePath
		if filePath == "" {
			errs = errors.Join(errs, fmt.Errorf("filePath is required"))
		} else {
			if _, ok := flowlogPaths[filePath]; ok {
				errs = errors.Join(errs, fmt.Errorf("duplicated flowlog path %s", filePath))
			}
			flowlogPaths[filePath] = struct{}{}
		}
	}

	return errs
}
