// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type DeletionFallbackClient struct {
	logger *logrus.Entry
	cli    *client.Client

	lockfile *lockfile.Lockfile
}

// the timeout for connecting and obtaining the lock
// the default of 30 seconds is too long; kubelet will time us out before then
const timeoutSeconds = 10

// the maximum number of queued deletions allowed, to protect against kubelet insanity
const maxDeletionFiles = 256

// NewDeletionFallbackClient creates a client that will either issue an EndpointDelete
// request via the api, *or* queue one in a temporary directory.
// To prevent race conditions, the logic is:
// 1. Try and connect to the socket. if that succeeds, done
// 2. Otherwise, take a shared lock on the delete queue directory
// 3. Once we get the lock, check to see if the socket now exists
// 4. If it exists, drop the lock and use the api
func NewDeletionFallbackClient(logger *logrus.Entry) (*DeletionFallbackClient, error) {
	dc := &DeletionFallbackClient{
		logger: logger,
	}

	// Try and connect (the usual case)
	err := dc.tryConnect()
	if err == nil {
		return dc, nil
	}
	dc.logger.WithError(err).Warnf("Failed to connect to agent socket at %s.", client.DefaultSockPath())

	// We failed to connect: get the queue lock
	if err := dc.tryQueueLock(); err != nil {
		return nil, fmt.Errorf("failed to acquire deletion queue: %w", err)
	}

	// We have the queue lock; try and connect again
	// just in case the agent finished starting up while we were waiting
	if err := dc.tryConnect(); err == nil {
		dc.logger.Info("Successfully connected to API on second try.")
		// hey, it's back up!
		dc.lockfile.Unlock()
		dc.lockfile = nil
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
	dc.logger.Debugf("attempting to acquire deletion queue lock at %s", defaults.DeleteQueueLockfile)

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
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	dc.lockfile = lf
	return nil
}

// EndpointDelete deletes an endpoint given by an endpoint id, either
// by directly accessing the API or dropping in a queued-deletion file.
// endpoint-id is a qualified endpoint reference, e.g. "container-id:XXXXXXX"
func (dc *DeletionFallbackClient) EndpointDelete(id string) error {
	if dc.cli != nil {
		return dc.cli.EndpointDelete(id)
	}

	// fall-back mode
	if dc.lockfile != nil {
		dc.logger.WithField(logfields.EndpointID, id).Info("Queueing deletion request for endpoint")

		// sanity check: if there are too many queued deletes, just return error
		// back up to the kubelet. If we get here, it's either because something
		// has gone wrong with the kubelet, or the agent has been down for a very
		// long time. To guard aganst long agent startup times (when it empties the
		// queue), limit us to 256 queued deletions. If this does, indeed, overflow,
		// then the kubelet will get the failure and eventually retry deletion.
		files, err := os.ReadDir(defaults.DeleteQueueDir)
		if err != nil {
			dc.logger.WithField(logfields.Path, defaults.DeleteQueueDir).WithError(err).Error("failed to list deletion queue directory")
			return err
		}
		if len(files) > maxDeletionFiles {
			return fmt.Errorf("deletion queue directory %s has too many entries; aborting", defaults.DeleteQueueDir)
		}

		// hash endpoint id for a random filename
		h := sha256.New()
		h.Write([]byte(id))
		filename := fmt.Sprintf("%x.delete", h.Sum(nil))
		path := filepath.Join(defaults.DeleteQueueDir, filename)

		err = os.WriteFile(path, []byte(id), 0644)
		if err != nil {
			dc.logger.WithField(logfields.Path, path).WithError(err).Error("failed to write deletion file")
			return fmt.Errorf("failed to write deletion file %s: %w", path, err)
		}
		dc.logger.Info("wrote queued deletion file")
		return nil
	}

	return fmt.Errorf("attempt to delete with no valid connection")
}
