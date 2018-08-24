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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

func getTempEndpointDirectory(origDir string) string {
	return origDir + "_next"
}

// synchronizeDirectories moves the files related to endpoint BPF program
// compilation to their according directories based on whether an error occurred
// during regeneration, or if compilation of BPF was necessary for the endpoint.
// Returns the original regenerationError if regenerationError was non-nil,
// or if any updates to directories for the endpoint's directories fails.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) synchronizeDirectories(origDir string, compilationExecuted bool, regenerationError error) error {
	scopedLog := e.getLogger()

	tmpDir := getTempEndpointDirectory(origDir)
	// If generation failed, keep the directory around. If it ever succeeds
	// again, clean up the XXX_next_fail copy.
	failDir := e.FailedDirectoryPath()
	os.RemoveAll(failDir) // Most likely will not exist; ignore failure.
	if regenerationError != nil {
		scopedLog.WithFields(logrus.Fields{
			logfields.Path: failDir,
		}).Warn("generating BPF for endpoint failed, keeping stale directory.")
		os.Rename(tmpDir, failDir)
		return regenerationError
	}

	// Move the current endpoint directory to a backup location
	backupDir := origDir + "_stale"
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

		return fmt.Errorf("restored original endpoint directory, atomic replace failed: %s", err)
	}

	// If the compilation was skipped then we need to copy the old bpf objects
	// into the new directory
	if !compilationExecuted {
		err := common.MoveNewFilesTo(backupDir, origDir)
		if err != nil {
			log.WithError(err).Debugf("unable to copy old bpf object "+
				"files from %s into the new directory %s.", backupDir, origDir)
		}
	}

	os.RemoveAll(backupDir)

	return nil
}
