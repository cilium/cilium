// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

type DeletionQueue struct {
	lf                     *lockfile.Lockfile
	endpointRestorePromise promise.Promise[endpointstate.Restorer]
	wg                     sync.WaitGroup
	endpointAPIManager     EndpointAPIManager
}

func (dq *DeletionQueue) Start(cell.HookContext) error {
	dq.wg.Add(1)
	go func() {
		defer dq.wg.Done()

		// hook context cancels when the start hooks have run, use context.Background()
		// as we may be running after that.
		_, err := dq.endpointRestorePromise.Await(context.Background())
		if err != nil {
			log.WithError(err).Error("deletionQueue: Daemon promise failed")
			return
		}

		if err := dq.lock(context.Background()); err != nil {
			return
		}

		err = dq.processQueuedDeletes(context.TODO())
		if err != nil {
			log.WithError(err).Error("deletionQueue: processQueuedDeletes failed")
		}
	}()
	return nil
}

func (dq *DeletionQueue) Stop(cell.HookContext) error {
	dq.wg.Wait()
	return nil
}

func newDeletionQueue(lc cell.Lifecycle, p promise.Promise[endpointstate.Restorer], endpointAPIManager EndpointAPIManager) *DeletionQueue {
	dq := &DeletionQueue{
		endpointRestorePromise: p,
		endpointAPIManager:     endpointAPIManager,
	}
	lc.Append(dq)
	return dq
}

func (dq *DeletionQueue) lock(ctx context.Context) error {
	if err := os.MkdirAll(defaults.DeleteQueueDir, 0755); err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueDir).Error("Failed to ensure CNI deletion queue directory exists")
		// Return error to avoid attempting successive df.processQueuedDeletes accessing
		// defaults.DeleteQueueLockfile and erroring because of the non-existent directory.
		return err
	}

	// Don't return a non-nil error from here on so a successive call to dq.processQueuedDeletes
	// can still continue with best effort.
	var err error
	dq.lf, err = lockfile.NewLockfile(defaults.DeleteQueueLockfile)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueLockfile).Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.")
		return nil
	}

	if err = dq.lf.Lock(ctx, true); err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueLockfile).Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.")
		dq.lf.Close()
		dq.lf = nil
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
func (dq *DeletionQueue) processQueuedDeletes(ctx context.Context) error {
	files, err := filepath.Glob(defaults.DeleteQueueDir + "/*.delete")
	if err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueDir).Error("Failed to list queued CNI deletion requests. CNI deletions may be missed.")
	}

	log.Infof("Processing %d queued deletion requests", len(files))

	for _, file := range files {
		err = dq.processQueuedDeleteEntryLocked(file)
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
func unlockAfterAPIServer(lc cell.Lifecycle, _ *server.Server, dq *DeletionQueue) {
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
func (dq *DeletionQueue) processQueuedDeleteEntryLocked(file string) error {
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
		_, _ = dq.endpointAPIManager.DeleteEndpoint(epID) // this will log errors elsewhere
		return nil
	}

	// As with DeleteEndpoint, errors are logged elsewhere
	_, _ = dq.endpointAPIManager.DeleteEndpointByContainerID(req.ContainerID)

	return nil
}
