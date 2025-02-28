// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// ExporterConfigParser is a configuration parser that returns instances of ExporterConfig mapped by
// a unique identifier.
type ExporterConfigParser interface {
	Parse(io.Reader) (configs map[string]ExporterConfig, err error)
}

// configWatcherCallback is a callback that receives successfully parsed configurations and the md5
// checksum of the source content.
type configWatcherCallback func(configs map[string]ExporterConfig, hash uint64)

// configWatcher provides dynamic configuration reload for DynamicExporter.
type configWatcher struct {
	logger         *slog.Logger
	configFilePath string
	configParser   ExporterConfigParser
	callback       configWatcherCallback
}

// NewConfigWatcher returns a new configWatcher that parses a configuration file using configParser
// and invokes callback at regular intervals.
func NewConfigWatcher(logger *slog.Logger, configFilePath string, configParser ExporterConfigParser, callback configWatcherCallback) *configWatcher {
	watcher := &configWatcher{
		logger: logger.With(
			logfields.LogSubsys, "hubble",
			logfields.ConfigFile, configFilePath,
		),
		configFilePath: configFilePath,
		configParser:   configParser,
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
	configs, hash, err := c.parseConfig()
	if err != nil {
		DynamicExporterReconfigurations.WithLabelValues("failure").Inc()
		c.logger.Error("Failed to parse dynamic exporter config", logfields.Error, err)
		return
	}
	c.callback(configs, hash)
}

func (c *configWatcher) parseConfig() (map[string]ExporterConfig, uint64, error) {
	content, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read config file %q: %w", c.configFilePath, err)
	}
	configs, err := c.configParser.Parse(bytes.NewReader(content))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse config file %q: %w", c.configFilePath, err)
	}
	hash := calculateHash(content)
	return configs, hash, nil
}

func calculateHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}
