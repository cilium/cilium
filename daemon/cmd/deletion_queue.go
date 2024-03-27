// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

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
//
// Returns a done function that drops the lock. It should be called
// after the server is running.
func (d *Daemon) processQueuedDeletes() func() {
	if err := os.MkdirAll(defaults.DeleteQueueDir, 0755); err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueDir).Error("Failed to ensure CNI deletion queue directory exists")
		return func() {}
	}

	log.Infof("Processing queued endpoint deletion requests from %s", defaults.DeleteQueueDir)

	var lf *lockfile.Lockfile
	locked := false

	unlock := func() {
		if lf != nil && locked {
			lf.Unlock()
		}
		if lf != nil {
			lf.Close()
		}
	}

	lf, err := lockfile.NewLockfile(defaults.DeleteQueueLockfile)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueLockfile).Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.")
	} else {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		defer cancel()
		err = lf.Lock(ctx, true)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueLockfile).Warn("Failed to lock queued deletion directory, proceeding anyways. This may cause CNI deletions to be missed.")
		} else {
			locked = true
		}
	}

	// OK, we have the lock; process the deletes
	files, err := filepath.Glob(defaults.DeleteQueueDir + "/*.delete")
	if err != nil {
		log.WithError(err).WithField(logfields.Path, defaults.DeleteQueueDir).Error("Failed to list queued CNI deletion requests. CNI deletions may be missed.")
	}

	log.Infof("processing %d queued deletion requests", len(files))
	for _, file := range files {
		err = d.processQueuedDeleteEntryLocked(file)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, file).Error("Failed to read queued CNI deletion entry. Endpoint will not be deleted.")
		}

		if err := os.Remove(file); err != nil {
			log.WithError(err).WithField(logfields.Path, file).Error("Failed to remve queued CNI deletion entry, but deletion was successful.")
		}
	}

	return unlock
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

	// As with DeleteEndpoint, errors are logged elsewhere
	_, _ = d.deleteEndpointByContainerID(req.ContainerID)

	return nil
}
