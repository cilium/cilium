// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"log/slog"
	"os"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

// EndpointMapManager is a wrapper around an endpointmanager as well as the
// filesystem for removing maps related to endpoints from the filesystem.
type EndpointMapManager struct {
	logger *slog.Logger
	endpointmanager.EndpointManager
}

// RemoveDatapathMapping unlinks the endpointID from the global policy map, preventing
// packets that arrive on this node from being forwarded to the endpoint that
// used to exist with the specified ID.
func (e *EndpointMapManager) RemoveDatapathMapping(endpointID uint16) error {
	return policymap.RemoveGlobalMapping(e.logger, uint32(endpointID))
}

// RemoveMapPath removes the specified path from the filesystem.
func (e *EndpointMapManager) RemoveMapPath(path string) {
	if err := os.RemoveAll(path); err != nil {
		e.logger.Warn(
			"Error while deleting stale map file",
			logfields.Path, path,
		)
	} else {
		e.logger.Info(
			"Removed stale bpf map",
			logfields.Path, path,
		)
	}
}

// ListMapsDir gives names of files (or subdirectories) found in the specified path.
func (e *EndpointMapManager) ListMapsDir(path string) []string {
	var maps []string

	entries, err := os.ReadDir(path)
	if err != nil {
		e.logger.Warn(
			"Error while listing maps dir",
			logfields.Path, path,
			logfields.Error, err,
		)
		return maps
	}

	for _, e := range entries {
		maps = append(maps, e.Name())
	}

	return maps
}
