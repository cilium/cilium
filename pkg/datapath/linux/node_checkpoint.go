// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/google/renameio/v2"
	jsoniter "github.com/json-iterator/go"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	nodesFilename                 = "nodes.json"
	nodeCheckpointMinInterval     = time.Minute
	nodeCheckpointCleanupRetryMin = time.Second
	nodeCheckpointCleanupRetryMax = time.Minute
)

type linuxNodeCheckpoint struct {
	log      *slog.Logger
	health   cell.Health
	db       *statedb.DB
	nodes    statedb.Table[*node.Node]
	cleaner  func(context.Context, nodeTypes.Node) error
	stateDir string

	mutex         lock.Mutex
	writeMutex    lock.Mutex
	restoredNodes map[nodeTypes.Identity]*nodeTypes.Node
	trigger       *trigger.Trigger
	done          chan struct{}
}

func newLinuxNodeCheckpoint(
	log *slog.Logger,
	health cell.Health,
	db *statedb.DB,
	nodes statedb.Table[*node.Node],
	cleaner func(context.Context, nodeTypes.Node) error,
	stateDir string,
) *linuxNodeCheckpoint {
	return &linuxNodeCheckpoint{
		log:           log,
		health:        health,
		db:            db,
		nodes:         nodes,
		cleaner:       cleaner,
		stateDir:      stateDir,
		restoredNodes: map[nodeTypes.Identity]*nodeTypes.Node{},
	}
}

func (c *linuxNodeCheckpoint) start() error {
	c.restore()
	c.done = make(chan struct{})
	health := c.health.NewScope("node-checkpoint-writer")

	var err error
	c.trigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "linux-node-checkpoint-trigger",
		MinInterval: nodeCheckpointMinInterval,
		TriggerFunc: func(reasons []string) {
			select {
			case <-c.done:
				return
			default:
			}
			if err := c.checkpoint(); err != nil {
				c.log.Error("Could not write node checkpoint",
					logfields.Error, err,
					logfields.Reasons, reasons,
				)
				health.Degraded("Failed to write node checkpoint", err)
			} else {
				health.OK("Node checkpoint written")
			}
		},
	})
	if err == nil {
		c.trigger.TriggerWithReason("Startup")
	}
	return err
}

func (c *linuxNodeCheckpoint) stop() error {
	if c.trigger == nil {
		return nil
	}
	c.trigger.Shutdown()
	close(c.done)
	err := c.checkpoint()
	c.trigger = nil
	return err
}

func (c *linuxNodeCheckpoint) restore() {
	path := filepath.Join(c.stateDir, nodesFilename)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			c.log.Debug("No node checkpoint found", logfields.Path, path)
		} else {
			c.log.Error("Failed to read node checkpoint",
				logfields.Path, path,
				logfields.Error, err,
			)
		}
		return
	}
	defer file.Close()

	var restored []*nodeTypes.Node
	decoder := jsoniter.ConfigFastest.NewDecoder(bufio.NewReader(file))
	if err := decoder.Decode(&restored); err != nil {
		c.log.Error("Failed to decode node checkpoint",
			logfields.Path, path,
			logfields.Error, err,
		)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, n := range restored {
		if !n.IsLocal() {
			n.Source = source.Restored
			c.restoredNodes[n.Identity()] = n
		}
	}
}

func (c *linuxNodeCheckpoint) watch(ctx context.Context, _ cell.Health) error {
	txn := c.db.ReadTxn()
	for {
		_, watch := c.nodes.AllWatch(txn)
		select {
		case <-ctx.Done():
			return nil
		case <-watch:
			c.trigger.TriggerWithReason("NodeTableChanged")
			txn = c.db.ReadTxn()
		}
	}
}

func (c *linuxNodeCheckpoint) prune(ctx context.Context, _ cell.Health) error {
	txn := c.db.ReadTxn()
	_, initWatch := c.nodes.Initialized(txn)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-initWatch:
		txn = c.db.ReadTxn()
	}

	c.mutex.Lock()
	for n := range c.nodes.All(txn) {
		delete(c.restoredNodes, n.Identity())
	}
	toDelete := slices.Collect(maps.Values(c.restoredNodes))
	c.mutex.Unlock()

	var errs error
	for _, n := range toDelete {
		if err := c.cleaner(ctx, *n); err != nil {
			errs = errors.Join(errs, fmt.Errorf(
				"cleaning restored node %s: %w",
				n.Identity(),
				err,
			))
			// Keep failed entries so the pruning job retries them and a later
			// checkpoint preserves them across another restart.
			continue
		}
		c.mutex.Lock()
		delete(c.restoredNodes, n.Identity())
		c.mutex.Unlock()
	}
	if c.trigger != nil {
		c.trigger.TriggerWithReason("RestoredNodesPruned")
	}
	return errs
}

func (c *linuxNodeCheckpoint) checkpoint() error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	nodesByIdentity := map[nodeTypes.Identity]nodeTypes.Node{}
	c.mutex.Lock()
	for identity, n := range c.restoredNodes {
		nodesByIdentity[identity] = *n
	}
	c.mutex.Unlock()

	for n := range c.nodes.All(c.db.ReadTxn()) {
		if !n.IsLocal() {
			nodesByIdentity[n.Identity()] = n.Node
		}
	}

	nodes := slices.Collect(maps.Values(nodesByIdentity))

	path := filepath.Join(c.stateDir, nodesFilename)
	file, err := renameio.TempFile(c.stateDir, path)
	if err != nil {
		return fmt.Errorf("opening temporary node checkpoint: %w", err)
	}
	defer file.Cleanup()

	buffer := bufio.NewWriter(file)
	if err := jsoniter.ConfigFastest.NewEncoder(buffer).Encode(nodes); err != nil {
		return fmt.Errorf("encoding node checkpoint: %w", err)
	}
	if err := buffer.Flush(); err != nil {
		return fmt.Errorf("flushing node checkpoint: %w", err)
	}
	return file.CloseAtomicallyReplace()
}
