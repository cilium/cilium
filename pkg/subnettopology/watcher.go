package subnettopology

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"sigs.k8s.io/yaml"
)

var (
	defaultWatchInterval = 5 * time.Second
)

type watcher struct {
	logger   *slog.Logger
	filePath string
	callback func(string, uint64) error
}

func newWatcher(logger *slog.Logger, filePath string, callback func(string, uint64) error) *watcher {
	return &watcher{
		logger:   logger,
		filePath: filePath,
		callback: callback,
	}
}

func (w *watcher) watch(ctx context.Context) error {
	w.logger.Info("Starting subnet topology watcher")
	ticker := time.NewTicker(defaultWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Subnet topology watcher stopped")
			return nil
		case <-ticker.C:
			w.reload()
		}
	}
}

func (w *watcher) reload() {
	newTopology, h, err := w.parse()
	if err != nil {
		w.logger.Error("failed to parse config", logfields.Error, err)
		return
	}
	w.callback(newTopology, h)
}

func (w *watcher) parse() (string, uint64, error) {
	content, err := os.ReadFile(w.filePath)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read config file: %w", err)
	}
	// Unmarshal the content into Config struct.
	// Assuming a YAML format for simplicity.
	var subnetTopology string
	if err := yaml.Unmarshal(content, &subnetTopology); err != nil {
		return "", 0, fmt.Errorf("failed to unmarshal config file: %w", err)
	}
	// Calculate the hash of the content.
	h := calculateHash(content)
	return subnetTopology, h, nil
}

func calculateHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}
