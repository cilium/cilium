// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// DirectoryPath returns the directory name for this endpoint bpf program.
func (e *Endpoint) DirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

// FailedDirectoryPath returns the directory name for this endpoint bpf program
// failed builds.
func (e *Endpoint) FailedDirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d%s", e.ID, "_next_fail"))
}

// NextDirectoryPath returns the directory name for this endpoint bpf program
// next bpf builds.
func (e *Endpoint) NextDirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d%s", e.ID, "_next"))
}

// synchronizeDirectories moves the files related to endpoint BPF program
// compilation to their according directories if compilation of BPF was
// necessary for the endpoint.
// Returns the original regenerationError if regenerationError was non-nil,
// or if any updates to directories for the endpoint's directories fails.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) synchronizeDirectories(origDir string, compilationExecuted bool) error {
	scopedLog := e.Logger()

	tmpDir := e.NextDirectoryPath()
	// If generation failed, keep the directory around. If it ever succeeds
	// again, clean up the XXX_next_fail copy.
	failDir := e.FailedDirectoryPath()
	os.RemoveAll(failDir) // Most likely will not exist; ignore failure.

	// Check if an existing endpoint directory exists, e.g.
	// /var/run/cilium/state/1111
	_, err := os.Stat(origDir)
	switch {

	// An endpoint directory already exists. We need to back it up before attempting
	// to move the new directory in its place so we can attempt recovery.
	case !os.IsNotExist(err):
		backupDir := origDir + "_stale"

		// Remove any eventual old backup directory. This may fail if
		// the directory does not exist. The error is deliberately
		// ignored.
		os.RemoveAll(backupDir)

		// Move the current endpoint directory to a backup location
		if err := os.Rename(origDir, backupDir); err != nil {
			os.RemoveAll(tmpDir)
			return fmt.Errorf("unable to rename current endpoint directory: %s", err)
		}

		// Make temporary directory the new endpoint directory
		if err := os.Rename(tmpDir, origDir); err != nil {
			os.RemoveAll(tmpDir)

			if err2 := os.Rename(backupDir, origDir); err2 != nil {
				scopedLog.WithFields(logrus.Fields{
					logfields.Path: backupDir,
				}).Warn("restoring directory for endpoint failed, endpoint " +
					"is in inconsistent state. Keeping stale directory.")
				return err2
			}

			return fmt.Errorf("restored original endpoint directory, atomic directory move failed: %s", err)
		}

		// If the compilation was skipped then we need to copy the old
		// bpf objects into the new directory
		if !compilationExecuted {
			err := common.MoveNewFilesTo(backupDir, origDir)
			if err != nil {
				log.WithError(err).Debugf("unable to copy old bpf object "+
					"files from %s into the new directory %s.", backupDir, origDir)
			}
		}

		os.RemoveAll(backupDir)

	// No existing endpoint directory, synchronizing the directory is a
	// simple move
	default:
		// Make temporary directory the new endpoint directory
		if err := os.Rename(tmpDir, origDir); err != nil {
			os.RemoveAll(tmpDir)
			return fmt.Errorf("atomic endpoint directory move failed: %s", err)
		}
	}

	return nil
}
