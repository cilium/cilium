package subnettopology

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
)

type dynamicManager struct {
	mu sync.Mutex

	logger   *slog.Logger
	filepath string

	hash   uint64
	subnet string

	wp *workerpool.WorkerPool
}

func registerDynamicManager(p Params) error {
	tm := &dynamicManager{
		logger: p.Logger.With(
			logfields.LogSubsys, "subnet-topology",
		),
		filepath: p.DaemonConfig.SubnetTopologyFilePath,
	}
	p.Lifecycle.Append(tm)
	return nil
}

func (tm *dynamicManager) Start(ctx cell.HookContext) error {
	tm.logger.Info("Starting subnet topology map")
	if tm.filepath == "" {
		tm.logger.Warn("No subnet topology file path configured, skipping watcher")
		return nil
	}
	w := newWatcher(tm.logger, tm.filepath, tm.onUpdate)

	tm.wp = workerpool.New(1)
	if err := tm.wp.Submit("subnet-topology-watcher", w.watch); err != nil {
		return fmt.Errorf("failed to start subnet topology watcher: %w", err)
	}
	return nil
}

func (tm *dynamicManager) Stop(ctx cell.HookContext) error {
	tm.logger.Info("Stopping subnet topology map")
	if tm.wp != nil {
		tm.wp.Close()
	}
	return nil
}

func (tm *dynamicManager) onUpdate(newSubnet string, newHash uint64) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if newHash == tm.hash {
		// No change in hash, nothing to update.
		return nil
	}

	// Sync eBPF map.

	tm.logger.Info("Sync'd eBPF map")
	tm.hash = newHash
	tm.subnet = newSubnet

	return nil
}
