// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type DeletionFallbackClient struct {
	logger *slog.Logger
	cli    *client.Client

	lockfile *lockfile.Lockfile
}

// the timeout for connecting and obtaining the lock
// the default of 30 seconds is too long; kubelet will time us out before then
const timeoutSeconds = 10

// the maximum number of queued deletions allowed, to protect against kubelet insanity
const maxDeletionFiles = 256

var (
	errServiceUnavailable = errors.New("cilium api not available")
)

// NewDeletionFallbackClient creates a client that will either issue an EndpointDelete
// request via the api, *or* queue one in a temporary directory.
// To prevent race conditions, the logic is:
// 1. Try and connect to the socket. if that succeeds, done
// 2. Otherwise, take a shared lock on the delete queue directory
// 3. Once we get the lock, check to see if the socket now exists
// 4. If it exists, drop the lock and use the api
func NewDeletionFallbackClient(logger *slog.Logger) (*DeletionFallbackClient, error) {
	dc := &DeletionFallbackClient{
		logger: logger,
	}

	// Try and connect (the usual case)
	err := dc.tryConnect()
	if err == nil {
		return dc, nil
	}
	dc.logger.Warn(
		"Failed to connect to agent socket",
		logfields.Error, err,
		logfields.Socket, client.DefaultSockPath(),
	)

	// We failed to connect: get the queue lock
	if err := dc.tryQueueLock(); err != nil {
		return nil, fmt.Errorf("failed to acquire deletion queue: %w", err)
	}

	// We have the queue lock; try and connect again
	// just in case the agent finished starting up while we were waiting
	if err := dc.tryConnect(); err == nil {
		dc.logger.Info("Successfully connected to API on second try.")
		// hey, it's back up!
		dc.unlockQueue()
		return dc, nil
	}

	// We have the lockfile, but no valid client
	dc.logger.Info("Agent is down, falling back to deletion queue directory")
	return dc, nil
}

func (dc *DeletionFallbackClient) tryConnect() error {
	c, err := client.NewDefaultClientWithTimeout(timeoutSeconds * time.Second)
	if err != nil {
		return err
	}
	dc.cli = c
	return nil
}

func (dc *DeletionFallbackClient) tryQueueLock() error {
	dc.logger.Debug(
		"Attempting to acquire deletion queue lock",
		logfields.Path, defaults.DeleteQueueLockfile,
	)
	startTime := time.Now()

	// Ensure deletion queue directory exists, obtain shared lock
	err := os.MkdirAll(defaults.DeleteQueueDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create deletion queue directory %s: %w", defaults.DeleteQueueDir, err)
	}

	lf, err := lockfile.NewLockfile(defaults.DeleteQueueLockfile)
	if err != nil {
		return fmt.Errorf("failed to open lockfile %s: %w", defaults.DeleteQueueLockfile, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutSeconds*time.Second)
	defer cancel()

	err = lf.Lock(ctx, false) // get the shared lock
	if err != nil {
		lf.Close()
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	dc.logger.Debug("Deletion Queue lock acquired",
		logfields.Path, defaults.DeleteQueueLockfile,
		logfields.Duration, time.Since(startTime))
	dc.lockfile = lf
	return nil
}

func (dc *DeletionFallbackClient) unlockQueue() {
	if dc.lockfile != nil {
		dc.lockfile.Unlock()
		dc.lockfile = nil
	}
}

// EndpointDeleteMany deletes multiple endpoints based on the endpoint deletion request,
// either by directly accessing the API or dropping in a queued-deletion file.
func (dc *DeletionFallbackClient) EndpointDeleteMany(req *models.EndpointBatchDeleteRequest) error {
	if dc.lockfile != nil {
		return dc.enqueueDeletionRequestLocked(req)
	}

	// If lock was not acquired, we have a valid client.
	err := dc.deleteEndpointsBatch(req)
	if err == nil || !errors.Is(err, errServiceUnavailable) {
		// Propagate the error if its not related to service unavailability.
		return err
	}

	// If the Endpoint Deletion request to cilium-agent failed, fallback to
	// queuing the deletion.
	dc.logger.Debug("Failed to delete Endpoints batch, ServiceUnvailable",
		logfields.Request, req,
		logfields.Error, err,
	)

	if err := dc.tryQueueLock(); err != nil {
		return fmt.Errorf("failed to acquire deletion queue lock: %w", err)
	}
	defer dc.unlockQueue()

	// We have the lock, we can retry deleting the endpoints.
	err = dc.deleteEndpointsBatch(req)

	// Only enqueue the Deletion request if the failure is API server related, so cilium-agent
	// can retry when DeletionQueue is replayed.
	if errors.Is(err, errServiceUnavailable) {
		return dc.enqueueDeletionRequestLocked(req)
	}

	return err
}

func (dc *DeletionFallbackClient) deleteEndpointsBatch(req *models.EndpointBatchDeleteRequest) error {
	err := dc.cli.EndpointDeleteMany(req)
	if err != nil {
		status, ok := err.(runtime.ClientResponseStatus)
		if !ok || !status.IsCode(http.StatusServiceUnavailable) {
			// Propagate unhandled server side Endpoint delete errors.
			return err
		}

		return errServiceUnavailable
	}

	return nil
}

// enqueueDeletionRequestLocked enqueues the encoded endpoint deletion request into the
// endpoint deletion queue. Requires the caller to hold the deletion queue lock.
func (dc *DeletionFallbackClient) enqueueDeletionRequestLocked(req *models.EndpointBatchDeleteRequest) error {
	dc.logger.Info(
		"Queueing endpoint batch deletion request",
		logfields.Request, req,
	)

	contents, err := req.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal endpoint delete request: %w", err)
	}

	// sanity check: if there are too many queued deletes, just return error
	// back up to the kubelet. If we get here, it's either because something
	// has gone wrong with the kubelet, or the agent has been down for a very
	// long time. To guard against long agent startup times (when it empties the
	// queue), limit us to 256 queued deletions. If this does, indeed, overflow,
	// then the kubelet will get the failure and eventually retry deletion.
	files, err := os.ReadDir(defaults.DeleteQueueDir)
	if err != nil {
		dc.logger.Error(
			"Failed to list deletion queue directory",
			logfields.Error, err,
			logfields.Path, defaults.DeleteQueueDir,
		)
		return err
	}
	if len(files) > maxDeletionFiles {
		return fmt.Errorf("deletion queue directory %s has too many entries; aborting", defaults.DeleteQueueDir)
	}

	// hash endpoint id for a random filename
	h := sha256.New()
	h.Write(contents)
	filename := fmt.Sprintf("%x.delete", h.Sum(nil))
	path := filepath.Join(defaults.DeleteQueueDir, filename)

	err = os.WriteFile(path, contents, 0644)
	if err != nil {
		dc.logger.Error(
			"Failed to write deletion file",
			logfields.Error, err,
			logfields.Path, path,
		)
		return fmt.Errorf("failed to write deletion file %s: %w", path, err)
	}
	dc.logger.Info("Wrote queued deletion file", logfields.Path, path)
	return nil
}
