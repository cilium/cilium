// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// DeletionQueue manages the processing of persisted CNI delete requests.
// This state is populated by CNI when the API is unreachable (agent restart),
// and is only processed *once* as a hive lifecycle job during startup.
type DeletionQueue struct {
	logger                 *slog.Logger
	lf                     *lockfile.Lockfile
	endpointRestorePromise promise.Promise[endpointstate.Restorer]
	endpointAPIManager     EndpointAPIManager
	processed              chan struct{}
}

func (dq *DeletionQueue) process(ctx context.Context, health cell.Health) error {
	restorer, err := dq.endpointRestorePromise.Await(ctx)
	if err != nil {
		dq.logger.Error("deletionQueue: failed to wait for restorer promise", logfields.Error, err)
		return fmt.Errorf("failed to wait for restorer promise: %w", err)
	}

	if err := restorer.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		dq.logger.Error("deletionQueue: failed to wait for endpoint restoration", logfields.Error, err)
		return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
	}

	dq.logger.Debug(
		"Attempting to acquire deletion queue lock",
		logfields.Path, defaults.DeleteQueueLockfile,
	)
	startTime := time.Now()
	if err := dq.lock(ctx); err != nil {
		return fmt.Errorf("unable to get exclusive lock: %w", err)
	}
	dq.logger.Debug("Deletion Queue lock acquired",
		logfields.Path, defaults.DeleteQueueLockfile,
		logfields.Duration, time.Since(startTime))

	// unlock lock file also in case of errors
	defer func() { close(dq.processed) }()

	if err := dq.processQueuedDeletes(ctx); err != nil {
		dq.logger.Error("deletionQueue: processQueuedDeletes failed", logfields.Error, err)
		return fmt.Errorf("processing queue failed: %w", err)
	}

	dq.logger.Debug("deletionQueue: successfully finished processing queue")

	return nil
}

type deletionQueueParams struct {
	cell.In

	Logger             *slog.Logger
	JobGroup           job.Group
	Restorer           promise.Promise[endpointstate.Restorer]
	EndpointAPIManager EndpointAPIManager
}

func newDeletionQueue(params deletionQueueParams) *DeletionQueue {
	dq := &DeletionQueue{
		logger:                 params.Logger,
		endpointRestorePromise: params.Restorer,
		endpointAPIManager:     params.EndpointAPIManager,
		processed:              make(chan struct{}),
	}

	params.JobGroup.Add(job.OneShot("cni-deletion-queue", dq.process))

	return dq
}

// Wait until the DeletionQueue processing is complete or the context is cancelled.
func (dq *DeletionQueue) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-dq.processed:
	}

	return nil
}

func (dq *DeletionQueue) lock(ctx context.Context) error {
	if err := os.MkdirAll(defaults.DeleteQueueDir, 0o755); err != nil {
		dq.logger.Error("Failed to ensure CNI deletion queue directory exists",
			logfields.Path, defaults.DeleteQueueDir,
			logfields.Error, err,
		)
		// Return error to avoid attempting successive df.processQueuedDeletes accessing
		// defaults.DeleteQueueLockfile and erroring because of the non-existent directory.
		return err
	}

	// Don't return a non-nil error from here on so a successive call to dq.processQueuedDeletes
	// can still continue with best effort.
	var err error
	dq.lf, err = lockfile.NewLockfile(defaults.DeleteQueueLockfile)
	if err != nil {
		dq.logger.Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.",
			logfields.Path, defaults.DeleteQueueLockfile,
			logfields.Error, err,
		)
		return nil
	}

	if err = dq.lf.Lock(ctx, true); err != nil {
		dq.logger.Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.",
			logfields.Path, defaults.DeleteQueueLockfile,
			logfields.Error, err,
		)
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
		dq.logger.Error("Failed to list queued CNI deletion requests. CNI deletions may be missed.",
			logfields.Path, defaults.DeleteQueueDir,
			logfields.Error, err,
		)
	}

	dq.logger.Info("Processing queued deletion requests", logfields.LenEndpoints, len(files))

	for _, file := range files {
		select {
		case <-ctx.Done():
			// stop processing on context cancellation
			return nil
		default:
		}

		err = dq.processQueuedDeleteEntryLocked(file)
		if err != nil {
			dq.logger.Error("Failed to read queued CNI deletion entry. Endpoint will not be deleted.",
				logfields.Path, file,
				logfields.Error, err,
			)
		}

		if err := os.Remove(file); err != nil {
			dq.logger.Error("Failed to remove queued CNI deletion entry, but deletion was successful.",
				logfields.Path, file,
				logfields.Error, err,
			)
		}
	}

	return nil
}

// unlockAfterAPIServer registers a start hook that runs after API server
// has started and the deletion queue has been drained to unlock the
// delete queue and thus allow CNI plugin to proceed.
func unlockAfterAPIServer(jobGroup job.Group, _ *server.Server, dq *DeletionQueue) {
	jobGroup.Add(job.OneShot("unlock-lockfile", func(ctx context.Context, health cell.Health) error {
		_ = dq.Wait(ctx)

		// Continue and release the lock on offline queue.
		if dq.lf != nil {
			unlockErr := dq.lf.Unlock()
			closeErr := dq.lf.Close()

			if unlockErr != nil || closeErr != nil {
				return fmt.Errorf("failed to unlock deletion queue lock file: %w", errors.Join(unlockErr, closeErr))
			}
		}

		return nil
	}))
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
		dq.logger.Debug("Falling back on legacy deletion queue format",
			logfields.EndpointID, epID,
			logfields.Error, err,
		)
		_, _ = dq.endpointAPIManager.DeleteEndpoint(epID) // this will log errors elsewhere
		return nil
	}

	// As with DeleteEndpoint, errors are logged elsewhere
	_, _ = dq.endpointAPIManager.DeleteEndpointByContainerID(req.ContainerID)

	return nil
}
