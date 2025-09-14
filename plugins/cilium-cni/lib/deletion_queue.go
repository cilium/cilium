// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type endpointDeleter func(params *endpoint.DeleteEndpointParams) error

const (
	// Max time to wait for deletion queue lock acquisition.
	queueLockWaitTimeout time.Duration = 3 * time.Second

	// The maximum number of queued deletions allowed, to protect against kubelet insanity.
	maxDeletionFiles int = 256
)

type DeletionFallbackClient struct {
	logger *slog.Logger

	deleteQueueDir      string
	deleteQueueLockfile string

	endpointDeleter endpointDeleter
}

var (
	// Indicates a non-recoverable error for DeletionFallbackClient.
	ErrClientFailure = errors.New("client failed")
)

func deleteCiliumEndpoint(params *endpoint.DeleteEndpointParams) error {
	c, err := client.NewDefaultClient()
	// Creating a cilium client can only fail during cilium socket path parsing.
	// This is either configured from environment variable(CILIUM_SOCK) or has
	// the default value - /var/run/cilium/cilium.sock
	if err != nil {
		return err
	}

	_, partialFailure, err := c.Endpoint.DeleteEndpoint(params)
	if partialFailure != nil {
		return partialFailure
	}

	return err
}

// NewDeletionFallbackClient creates a new deletion client.
func NewDeletionFallbackClient(logger *slog.Logger) *DeletionFallbackClient {
	return &DeletionFallbackClient{
		logger: logger,

		deleteQueueDir:      defaults.DeleteQueueDir,
		deleteQueueLockfile: defaults.DeleteQueueLockfile,

		endpointDeleter: deleteCiliumEndpoint,
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), queueLockWaitTimeout)
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

	dc.logger.Debug("Failed to delete Endpoints batch, queueing request",
		logfields.Request, req,
		logfields.Error, err,
	)

	lf, err := dc.tryQueueLock()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientFailure, err)
	}
	defer lf.Unlock()

	// We have the lock now.
	// Retry deleting the endpoint batch, in case cilium-agent is able to process the
	// request now.
	fallback, err = dc.deleteEndpointsBatch(req)
	if !fallback {
		dc.logger.Debug("Endpoint batch delete processed on second attempt", logfields.Error, err)
		return err
	}

	// Enqueue the deletion request to be replayed by cilium-agent during startup.
	err = dc.enqueueDeletionRequestLocked(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientFailure, err)
	}

	return nil
}

// deleteEndpointsBatch attempts to connect to cilium api and request endpoint deletion for the provided
// request. If either the connection fails or Endpoint API is not available, this method returns true
// indicating the caller to attempt fallback logic.
func (dc *DeletionFallbackClient) deleteEndpointsBatch(req *models.EndpointBatchDeleteRequest) (bool, error) {
	delParams := endpoint.NewDeleteEndpointParams().WithEndpoint(req).WithTimeout(api.ClientTimeout)

	err := dc.endpointDeleter(delParams)
	if err != nil {
		var (
			partialErrs *endpoint.DeleteEndpointErrors
			notFoundErr *endpoint.DeleteEndpointNotFound
			invalidErr  *endpoint.DeleteEndpointInvalid

			serviceUnavailableErr *endpoint.DeleteEndpointServiceUnavailable
			tooManyReqErr         *endpoint.DeleteEndpointTooManyRequests
		)

		switch {
		// Partial failure. Don't fallback, log and bubble up error.
		case errors.As(err, &partialErrs):
			return false, err
		// Don't fallback for known non-retryable errors.
		case errors.As(err, &notFoundErr), errors.As(err, &invalidErr):
			return false, err
		// Attempt fallback if endpoint service didn't get a chance to process the request.
		case errors.As(err, &serviceUnavailableErr), errors.As(err, &tooManyReqErr):
			return true, err
		// For unknown or connection related failures always attempt fallback.
		default:
			return true, err
		}
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
