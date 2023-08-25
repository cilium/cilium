// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	nextDirectorySuffix       = "_next"
	nextFailedDirectorySuffix = "_next_fail"
	backupDirectorySuffix     = "_stale"
)

// DirectoryPath returns the directory name for this endpoint bpf program.
func (e *Endpoint) DirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

// FailedDirectoryPath returns the directory name for this endpoint bpf program
// failed builds.
func (e *Endpoint) FailedDirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d%s", e.ID, nextFailedDirectorySuffix))
}

// StateDirectoryPath returns the directory name for this endpoint bpf program.
func (e *Endpoint) StateDirectoryPath() string {
	return filepath.Join(option.Config.StateDir, e.StringID())
}

// NextDirectoryPath returns the directory name for this endpoint bpf program
// next bpf builds.
func (e *Endpoint) NextDirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d%s", e.ID, nextDirectorySuffix))
}

func (e *Endpoint) backupDirectoryPath() string {
	return e.DirectoryPath() + backupDirectorySuffix
}

// moveNewFilesTo copies all files, that do not exist in newDir, from oldDir.
// It assumes that oldDir and newDir are an endpoint's old and new state
// directories (see synchronizeDirectories below).
func moveNewFilesTo(oldDir, newDir string) error {
	var err error

	oldDirFile, err := os.Open(oldDir)
	if err != nil {
		return fmt.Errorf("failed to open old endpoint state dir: %w", err)
	}
	defer oldDirFile.Close()

	oldFiles, err := oldDirFile.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("failed to list old endpoint state dir: %w", err)
	}

	newDirFile, err := os.Open(newDir)
	if err != nil {
		return fmt.Errorf("failed to open new endpoint state dir: %w", err)
	}
	defer newDirFile.Close()

	newFiles, err := newDirFile.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("failed to list new endpoint state dir: %w", err)
	}

	newFilesHash := make(map[string]struct{}, len(newFiles))
	for _, f := range newFiles {
		newFilesHash[f] = struct{}{}
	}

	var ok bool

	for _, oldFile := range oldFiles {
		if _, ok = newFilesHash[oldFile]; !ok {
			if err := os.Rename(filepath.Join(oldDir, oldFile), filepath.Join(newDir, oldFile)); err != nil {
				return fmt.Errorf("failed to move endpoint state file: %w", err)
			}
		}
	}

	return nil
}

// synchronizeDirectories moves the files related to endpoint BPF program
// compilation to their according directories if compilation of BPF was
// necessary for the endpoint.
// Returns the original regenerationError if regenerationError was non-nil,
// or if any updates to directories for the endpoint's directories fails.
// Must be called with endpoint.mutex Lock()ed.
func (e *Endpoint) synchronizeDirectories(origDir string, stateDirComplete bool) error {
	scopedLog := e.getLogger()
	debugLogEnabled := logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel)

	scopedLog.Debug("synchronizing directories")

	tmpDir := e.NextDirectoryPath()

	// Check if an existing endpoint directory exists, e.g.
	// /var/run/cilium/state/1111
	_, err := os.Stat(origDir)
	switch {

	// An endpoint directory already exists. We need to back it up before attempting
	// to move the new directory in its place so we can attempt recovery.
	case !os.IsNotExist(err):
		scopedLog.Debug("endpoint directory exists; backing it up")
		backupDir := e.backupDirectoryPath()

		// Remove any eventual old backup directory. This may fail if
		// the directory does not exist. The error is deliberately
		// ignored.
		e.removeDirectory(backupDir)

		// Move the current endpoint directory to a backup location
		if debugLogEnabled {
			scopedLog.WithFields(logrus.Fields{
				"originalDirectory": origDir,
				"backupDirectory":   backupDir,
			}).Debug("moving current directory to backup location")
		}

		if err := os.Rename(origDir, backupDir); err != nil {
			return fmt.Errorf("unable to rename current endpoint directory: %s", err)
		}

		// Regarldess of whether the atomic replace succeeds or not,
		// ensure that the backup directory is removed when the
		// function returns.
		defer e.removeDirectory(backupDir)

		// Make temporary directory the new endpoint directory
		if err := os.Rename(tmpDir, origDir); err != nil {
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
		if !stateDirComplete {
			scopedLog.Debug("some BPF state files were not recreated; moving old BPF objects into new directory")
			err := moveNewFilesTo(backupDir, origDir)
			if err != nil {
				log.WithError(err).Debugf("unable to copy old bpf object "+
					"files from %s into the new directory %s.", backupDir, origDir)
			}
		}

	// No existing endpoint directory, synchronizing the directory is a
	// simple move
	default:
		// Make temporary directory the new endpoint directory
		if debugLogEnabled {
			scopedLog.WithFields(logrus.Fields{
				"temporaryDirectory": tmpDir,
				"originalDirectory":  origDir,
			}).Debug("attempting to make temporary directory new directory for endpoint programs")
		}

		if err := os.Rename(tmpDir, origDir); err != nil {
			return fmt.Errorf("atomic endpoint directory move failed: %s", err)
		}
	}

	// The build succeeded and is in place, any eventual existing failure
	// directory can be removed.
	e.removeDirectory(e.FailedDirectoryPath())

	return nil
}

func (e *Endpoint) removeDirectory(path string) error {
	if logger := e.getLogger(); logging.CanLogAt(logger.Logger, logrus.DebugLevel) {
		logger.WithField("directory", path).Debug("removing directory")
	}
	return os.RemoveAll(path)
}

func (e *Endpoint) removeDirectories() {
	e.removeDirectory(e.DirectoryPath())
	e.removeDirectory(e.FailedDirectoryPath())
	e.removeDirectory(e.NextDirectoryPath())
	e.removeDirectory(e.backupDirectoryPath())
}
