// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

var deletionQueueCell = cell.Group(
	cell.Provide(newDeletionQueue),
	cell.Invoke(unlockAfterAPIServer),
)

type deletionQueue struct {
	lf            *lockfile.Lockfile
	daemonPromise promise.Promise[*Daemon]
	wg            sync.WaitGroup
}

func (dq *deletionQueue) Start(cell.HookContext) error {
	dq.wg.Add(1)
	go func() {
		defer dq.wg.Done()

		// hook context cancels when the start hooks have run, use context.Background()
		// as we may be running after that.
		d, err := dq.daemonPromise.Await(context.Background())
		if err != nil {
			log.WithError(err).Error("deletionQueue: Daemon promise failed")
			return
		}

		if err := dq.lock(d.ctx); err != nil {
			log.WithError(err).Error("deletionQueue: lock failed")
			return
		}

		bootstrapStats.deleteQueue.Start()
		err = dq.processQueuedDeletes(d, d.ctx)
		bootstrapStats.deleteQueue.EndError(err)
		if err != nil {
			log.WithError(err).Error("deletionQueue: processQueuedDeletes failed")
		}
	}()
	return nil
}

func (dq *deletionQueue) Stop(cell.HookContext) error {
	dq.wg.Wait()
	return nil
}

func newDeletionQueue(lc cell.Lifecycle, p promise.Promise[*Daemon]) *deletionQueue {
	dq := &deletionQueue{daemonPromise: p}
	lc.Append(dq)
	return dq
}

func (dq *deletionQueue) lock(ctx context.Context) error {
	if err := os.MkdirAll(defaults.DeleteQueueDir, 0755); err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueDir).Error("Failed to ensure CNI deletion queue directory exists")
		return nil
	}

	var err error
	dq.lf, err = lockfile.NewLockfile(defaults.DeleteQueueLockfile)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueLockfile).Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.")
	} else {
		err = dq.lf.Lock(ctx, true)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueLockfile).Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.")
			dq.lf.Close()
			dq.lf = nil
		}
	}
	return nil
}

// processQueuedDeletes is the agent-side of the identity deletion queue.
// The CNI plugin queues deletions when the agent is down, because
// containerd / crio expect CNI DEL to always succeed. It does so
// by writing a file to /run/cilium/deleteQueue with the endpoint ID
// to delete.
//
// On startup, we will grab a lockfile in this directory, then process
// all deletions. Then, we start up the agent server, then drop the lock.
// Any CNI processes waiting in that period of time will, after getting
// the lock.
func (dq *deletionQueue) processQueuedDeletes(d *Daemon, ctx context.Context) error {
	files, err := filepath.Glob(defaults.DeleteQueueDir + "/*.delete")
	if err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueDir).Error("Failed to list queued CNI deletion requests. CNI deletions may be missed.")
	}

	log.Infof("Processing %d queued deletion requests", len(files))

	for _, file := range files {
		err = d.processQueuedDeleteEntryLocked(file)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, file).Error("Failed to read queued CNI deletion entry. Endpoint will not be deleted.")
		}

		if err := os.Remove(file); err != nil {
			log.WithError(err).WithField(logfields.Path, file).Error("Failed to remove queued CNI deletion entry, but deletion was successful.")
		}
	}

	return nil
}

// unlockAfterAPIServer registers a start hook that runs after API server
// has started and the deletion queue has been drained to unlock the
// delete queue and thus allow CNI plugin to proceed.
func unlockAfterAPIServer(lc cell.Lifecycle, _ *server.Server, dq *deletionQueue) {
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if dq.lf != nil {
				dq.lf.Unlock()
				dq.lf.Close()
			}
			return nil
		},
	})
}

// processQueuedDeleteEntry processes the contents of the deletion queue entry
// in file. Requires the caller to hold the deletion queue lock.
func (d *Daemon) processQueuedDeleteEntryLocked(file string) error {
	contents, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	// Attempt to parse contents as a batch deletion request
	var req models.EndpointBatchDeleteRequest
	err = req.UnmarshalBinary(contents)
	if err != nil {
		// fall back on treating the file contents as an endpoint id (legacy behavior)
		epID := string(contents)
		log.
			WithError(err).
			WithField(logfields.EndpointID, epID).
			Debug("Falling back on legacy deletion queue format")
		_, _ = d.DeleteEndpoint(epID) // this will log errors elsewhere
		return nil
	}

	fmt.Println("[tom-debug] delete from queue:", file, req.ContainerID)
	// As with DeleteEndpoint, errors are logged elsewhere
	_, _ = d.deleteEndpointByContainerID(req.ContainerID)

	return nil
}
