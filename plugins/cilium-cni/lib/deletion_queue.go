// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
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

type ciliumClient interface {
	EndpointDeleteMany(*models.EndpointBatchDeleteRequest) error
}

type newCiliumClientFn func(time.Duration) (ciliumClient, error)

type DeletionFallbackClient struct {
	logger *slog.Logger
	cli    ciliumClient

	deleteQueueDir      string
	deleteQueueLockfile string

	newCiliumClientFn newCiliumClientFn

	connectionBackoff time.Duration
}

const (
	// the timeout for connecting and obtaining the lock
	// the default of 30 seconds is too long; kubelet will time us out before then
	timeoutDuration = 1500 * time.Millisecond

	// default backoff interval between two subsequent connection attempts to the agent
	connectionBackoffDefault = 5 * time.Second

	// the maximum number of queued deletions allowed, to protect against kubelet insanity
	maxDeletionFiles = 256
)

var (
	// Indicates a non-recoverable error for DeletionFallbackClient.
	ErrClientFailure = errors.New("client failed")
)

func newCiliumClient(timeout time.Duration) (ciliumClient, error) {
	return client.NewDefaultClientWithTimeout(timeout)
}

// NewDeletionFallbackClient creates a new deletion client.
func NewDeletionFallbackClient(logger *slog.Logger) *DeletionFallbackClient {
	return &DeletionFallbackClient{
		logger: logger,

		deleteQueueDir:      defaults.DeleteQueueDir,
		deleteQueueLockfile: defaults.DeleteQueueLockfile,

		newCiliumClientFn: newCiliumClient,

		connectionBackoff: connectionBackoffDefault,
	}
}

func (dc *DeletionFallbackClient) tryConnect() error {
	if dc.cli != nil {
		return nil
	}

	c, err := dc.newCiliumClientFn(timeoutDuration)
	if err != nil {
		return err
	}
	dc.cli = c
	return nil
}

func (dc *DeletionFallbackClient) tryQueueLock() (*lockfile.Lockfile, error) {
	dc.logger.Debug(
		"Attempting to acquire deletion queue lock",
		logfields.Path, dc.deleteQueueLockfile,
	)
	startTime := time.Now()

	// Ensure deletion queue directory exists, obtain shared lock
	err := os.MkdirAll(dc.deleteQueueDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create deletion queue directory %s: %w", dc.deleteQueueDir, err)
	}

	lf, err := lockfile.NewLockfile(dc.deleteQueueLockfile)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile %s: %w", dc.deleteQueueLockfile, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	err = lf.Lock(ctx, false) // get the shared lock
	if err != nil {
		lf.Close()
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	dc.logger.Debug("Deletion Queue lock acquired",
		logfields.Path, dc.deleteQueueLockfile,
		logfields.Duration, time.Since(startTime))
	return lf, nil
}

// EndpointDeleteMany deletes multiple endpoints based on the endpoint deletion request,
// either by directly accessing the API or dropping in a queued-deletion file.
//
// To prevent race conditions, the logic is:
// 1. Try and connect to the socket and request deletion. if that succeeds, done.
// 2. Otherwise, take a shared lock on the delete queue directory.
// 3. Once we have the lock, check again to see if the deletion request succeeds.
// 4. Persist the request to offline queue in case of failure.
//
// Endpoint Deletion handled by this method returns two types of errors:
// 1. Delete request processing errors propagated from cilium-agent(eg. NotFound, Invalid)
// 2. Client failure indicating a non-recoverable error(eg. when deletion queue locking during fallback fails)
func (dc *DeletionFallbackClient) EndpointDeleteMany(req *models.EndpointBatchDeleteRequest) error {
	fallback, err := dc.deleteEndpointsBatch(req)
	if err == nil || !fallback {
		return err
	}

	// If the Endpoint Deletion request to cilium-agent failed, fallback to
	// queuing the deletion.
	dc.logger.Debug("Failed to delete Endpoints batch",
		logfields.Request, req,
		logfields.Error, err,
	)

	lf, err := dc.tryQueueLock()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientFailure, err)
	}
	defer lf.Unlock()

	// We have the lock now, we can retry deleting the endpoints.
	fallback, err = dc.deleteEndpointsBatch(req)

	// Only enqueue the Deletion request if the failure is API server related, so cilium-agent
	// can process the request when DeletionQueue is replayed.
	if fallback {
		err = dc.enqueueDeletionRequestLocked(req)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrClientFailure, err)
		}
	}

	return err
}

// deleteEndpointsBatch attempts to connect to cilium api and request endpoint deletion for the provided
// request. If either the connection fails or Endpoint API is not available, this method returns true
// indicating the caller to attempt fallback logic.
func (dc *DeletionFallbackClient) deleteEndpointsBatch(req *models.EndpointBatchDeleteRequest) (bool, error) {
	if err := dc.tryConnect(); err != nil {
		// Check if agent is starting up. If so, it is about to handle the
		// deletion queue, thus we should avoid taking the lock in order to
		// reduce contention.
		// Instead, we wait for it to complete its bootstrap and retry to
		// connect again later.
		var dirExists, socketNotExists bool
		if _, err := os.Stat(filepath.Dir(client.DefaultSockPath())); err == nil {
			dirExists = true
		}
		if _, err := os.Stat(client.DefaultSockPath()); errors.Is(err, fs.ErrNotExist) {
			socketNotExists = true
		}
		if !dirExists || !socketNotExists {
			// Agent is not bootstrapping
			return true, err
		}

		for range 3 {
			dc.logger.Info("Agent is starting up, will retry to connect to the agent socket again in 5 seconds")
			time.Sleep(dc.connectionBackoff)
			if err := dc.tryConnect(); err == nil {
				dc.logger.Info("Successfully connected to the API after waiting for the agent to start")
				break
			}
		}
		if dc.cli == nil {
			// Failed to setup cilium client.
			return true, err
		}
	}

	err := dc.cli.EndpointDeleteMany(req)
	if err != nil {
		status, ok := err.(runtime.ClientResponseStatus)
		if !ok || !status.IsCode(http.StatusServiceUnavailable) {
			// Propagate unhandled server side Endpoint delete errors.
			return false, err
		}

		// Endpoint API is unavailable.
		return true, err
	}

	// Endpoint deleted successfully.
	return false, nil
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
	files, err := os.ReadDir(dc.deleteQueueDir)
	if err != nil {
		dc.logger.Error(
			"Failed to list deletion queue directory",
			logfields.Error, err,
			logfields.Path, dc.deleteQueueDir,
		)
		return err
	}
	if len(files) > maxDeletionFiles {
		return fmt.Errorf("deletion queue directory %s has too many entries; aborting", dc.deleteQueueDir)
	}

	// hash endpoint id for a random filename
	h := sha256.New()
	h.Write(contents)
	filename := fmt.Sprintf("%x.delete", h.Sum(nil))
	path := filepath.Join(dc.deleteQueueDir, filename)

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
