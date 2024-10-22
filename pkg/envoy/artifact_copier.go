// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ArtifactCopier provides support for copying artifacts from a given source directory to a target directory.
// This is mainly used to copy additional artifacts referenced by the Envoy proxy configuration from the Cilium agent
// container to the config directory that is shared with the Envoy container if Envoy is running in a dedicated DaemonSet.
type ArtifactCopier struct {
	sourcePath string
	targetPath string
}

// Copy copies all files within the given sourcePath directory into the targetPath directory.
//
// If targetPath already exists, all existing files within the directory are deleted before starting the copy process.
// If targetPath doesn't exist, it gets created automatically before starting the copy process.
func (r *ArtifactCopier) Copy() (err error) {
	if _, err := os.Stat(r.sourcePath); os.IsNotExist(err) {
		log.WithField("source-path", r.sourcePath).
			Debugf("Envoy: No artifacts to copy to envoy - source path doesn't exist")
		return nil
	}

	// Wipe target directory if it exists
	if ti, err := os.Stat(r.targetPath); err == nil && ti.IsDir() {
		log.WithField("target-path", r.sourcePath).
			Debugf("Envoy: Clean target directory")

		if err := r.cleanTargetDirectory(); err != nil {
			return fmt.Errorf("failed to clean target directory: %w", err)
		}
	}

	log.WithField("source-path", r.sourcePath).
		WithField("target-path", r.targetPath).
		Infof("Envoy: Copy artifacts to envoy")

	return r.copyFiles(r.sourcePath, r.targetPath)
}

func (r *ArtifactCopier) cleanTargetDirectory() error {
	entries, err := os.ReadDir(r.targetPath)
	if err != nil {
		return fmt.Errorf("failed to get target directory content: %w", err)
	}

	for _, entry := range entries {
		path := filepath.Join(r.targetPath, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to delete existing content in target directory: %w", err)
		}
	}

	return nil
}

func (r *ArtifactCopier) copyFiles(src string, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	if _, err := os.Stat(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to get source directory info: %w", err)
	}

	if err := os.MkdirAll(dst, si.Mode()); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read directory content: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if !entry.IsDir() {
			// Skip symlinks.
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}

			if err = r.copyFile(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to copy file: %w", err)
			}
		}
	}

	return nil
}

func (r *ArtifactCopier) copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create target file: %w", err)
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	if err = out.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	return nil
}
