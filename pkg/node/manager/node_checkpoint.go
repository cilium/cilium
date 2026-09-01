// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
	jsoniter "github.com/json-iterator/go"

	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	// The filename for the nodes checkpoint. This is periodically written, and
	// restored on restart. The default path is /run/cilium/state/nodes.json
	nodesFilename = "nodes.json"
	// Minimum amount of time to wait in between writing nodes file.
	nodeCheckpointMinInterval = time.Minute
)

func (m *manager) restoreNodeCheckpoint() {
	path := filepath.Join(m.conf.StateDir, nodesFilename)
	scopedLog := m.logger.With(logfields.Path, path)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If we don't have a file to restore from, there's nothing we can
			// do. This is expected in the upgrade path.
			scopedLog.Debug(
				fmt.Sprintf("No %v file found, cannot replay node deletion events for nodes"+
					" which disappeared during downtime.", nodesFilename),
			)
			return
		}
		scopedLog.Error(
			"failed to read node checkpoint file",
			logfields.Error, err,
		)
		return
	}
	defer f.Close()

	r := jsoniter.ConfigFastest.NewDecoder(bufio.NewReader(f))
	var nodeCheckpoint []*nodeTypes.Node
	if err := r.Decode(&nodeCheckpoint); err != nil {
		scopedLog.Error(
			"failed to decode node checkpoint file",
			logfields.Error, err,
		)
		return
	}

	// We can't call NodeUpdated for restored nodes here, as the machinery
	// assumes a fully initialized node manager, which we don't currently have.
	// In addition, we only want to replay NodeDeletions, since k8s provided
	// up-to-date information on all live nodes. We keep the restored nodes
	// separate, let whatever init needs to happen occur and once we're synced
	// to k8s, compare the restored nodes to the live ones.
	for _, n := range nodeCheckpoint {
		if !n.IsLocal() {
			n.Source = source.Restored
			m.restoredNodes[n.Identity()] = n
		}
	}
}

// initNodeCheckpointer sets up the trigger for writing nodes to disk.
func (m *manager) initNodeCheckpointer(minInterval time.Duration) error {
	var err error
	health := m.health.NewScope("node-checkpoint-writer")
	m.checkpointerDone = make(chan struct{})

	m.nodeCheckpointer, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "node-checkpoint-trigger",
		MinInterval: minInterval, // To avoid rapid repetition (e.g. during startup).
		TriggerFunc: func(reasons []string) {
			m.mutex.RLock()
			select {
			// The trigger package does not check whether the trigger is shut
			// down already after sleeping to honor the MinInterval. Hence, we
			// do so ourselves.
			case <-m.checkpointerDone:
				return
			default:
			}
			err := m.checkpoint()
			m.mutex.RUnlock()

			if err != nil {
				m.logger.Error(
					"could not write node checkpoint",
					logfields.Error, err,
					logfields.Reasons, reasons,
				)
				health.Degraded("failed to write node checkpoint", err)
			} else {
				health.OK("node checkpoint written")
			}
		},
	})
	return err
}

// checkpoint writes all nodes to disk. Assumes the manager is read locked.
// Don't call this directly, use the nodeCheckpointer trigger.
func (m *manager) checkpoint() error {
	stateDir := m.conf.StateDir
	nodesPath := filepath.Join(stateDir, nodesFilename)
	m.logger.Debug(
		"writing node checkpoint to disk",
		logfields.Path, nodesPath,
	)

	// Write new contents to a temporary file which will be atomically renamed to the
	// real file at the end of this function to avoid data corruption if we crash.
	f, err := renameio.TempFile(stateDir, nodesPath)
	if err != nil {
		return fmt.Errorf("failed to open temporary file: %w", err)
	}
	defer f.Cleanup()

	bw := bufio.NewWriter(f)
	w := jsoniter.ConfigFastest.NewEncoder(bw)
	ns := make([]nodeTypes.Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		if !n.node.IsLocal() {
			ns = append(ns, n.node)
		}
	}
	if err := w.Encode(ns); err != nil {
		return fmt.Errorf("failed to encode node checkpoint: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("failed to flush node checkpoint writer: %w", err)
	}

	return f.CloseAtomicallyReplace()
}
