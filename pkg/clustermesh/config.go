// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"crypto/sha256"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

// clusterLifecycle is the interface to implement in order to receive cluster
// configuration lifecycle events. This is implemented by the ClusterMesh.
type clusterLifecycle interface {
	add(clusterName, clusterConfigPath string)
	remove(clusterName string)
}

type fhash [sha256.Size]byte

type configDirectoryWatcher struct {
	watcher   *fsnotify.Watcher
	lifecycle clusterLifecycle
	path      string
	tracked   map[string]fhash
	stop      chan struct{}
}

func createConfigDirectoryWatcher(path string, lifecycle clusterLifecycle) (*configDirectoryWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return nil, err
	}

	return &configDirectoryWatcher{
		watcher:   watcher,
		path:      path,
		tracked:   map[string]fhash{},
		lifecycle: lifecycle,
		stop:      make(chan struct{}),
	}, nil
}

// isEtcdConfigFile returns whether the given path looks like a configuration
// file, and in that case it returns the corresponding hash to detect modifications.
func isEtcdConfigFile(path string) (bool, fhash) {
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return false, fhash{}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return false, fhash{}
	}

	// search for the "endpoints:" string
	if strings.Contains(string(b), "endpoints:") {
		return true, sha256.Sum256(b)
	}

	return false, fhash{}
}

func (cdw *configDirectoryWatcher) handle(abspath string) {
	filename := path.Base(abspath)
	isConfig, newHash := isEtcdConfigFile(abspath)

	if !isConfig {
		// If the corresponding cluster was tracked, then trigger the remove
		// event, since the configuration file is no longer present/readable
		if _, tracked := cdw.tracked[filename]; tracked {
			log.WithFields(logrus.Fields{
				fieldClusterName: filename,
				fieldConfig:      abspath,
			}).Debug("Removed cluster configuration")

			// The remove operation returns an error if the file does no longer exists.
			_ = cdw.watcher.Remove(abspath)
			delete(cdw.tracked, filename)
			cdw.lifecycle.remove(filename)
		}

		return
	}

	if !slices.Contains(cdw.watcher.WatchList(), abspath) {
		// Start watching explicitly the file. This allows to receive a notification
		// when the underlying file gets updated, if path points to a symbolic link.
		// This is required to correctly detect file modifications when the folder
		// is mounted from a Kubernetes ConfigMap/Secret.
		if err := cdw.watcher.Add(abspath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.WithError(err).WithField(fieldConfig, abspath).
				Warning("Failed adding explicit path watch for config")
		} else {
			// There is a small chance that the file content changed in the time
			// window from reading it at the beginning of the function to establishing
			// the watcher. To avoid missing that possible update, let's re-read the
			// file, so that we are sure to process the most up-to-date version.
			// This prevents issues when modifying the same file twice back-to-back.
			// We don't recurse in case a failure occurred when registering the
			// watcher (except for NotFound) to prevent an infinite loop if
			// something wrong happened.
			cdw.handle(abspath)
		}
	}

	oldHash, tracked := cdw.tracked[filename]

	// Do not emit spurious notifications if the config file did not change.
	if tracked && oldHash == newHash {
		return
	}

	log.WithFields(logrus.Fields{
		fieldClusterName: filename,
		fieldConfig:      abspath,
	}).Debug("Added or updated cluster configuration")

	cdw.tracked[filename] = newHash
	cdw.lifecycle.add(filename, abspath)
}

func (cdw *configDirectoryWatcher) watch() error {
	log.WithField(fieldConfigDir, cdw.path).Debug("Starting config directory watcher")

	files, err := os.ReadDir(cdw.path)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		absolutePath := path.Join(cdw.path, f.Name())
		cdw.handle(absolutePath)
	}

	go cdw.loop()
	return nil
}

func (cdw *configDirectoryWatcher) loop() {
	for {
		select {
		case event := <-cdw.watcher.Events:
			log.WithFields(logrus.Fields{
				fieldConfigDir: cdw.path,
				fieldEvent:     event,
			}).Debug("Received fsnotify event")
			cdw.handle(event.Name)

		case err := <-cdw.watcher.Errors:
			log.WithError(err).WithField(fieldConfigDir, cdw.path).
				Warning("Error encountered while watching directory with fsnotify")

		case <-cdw.stop:
			return
		}
	}
}

func (cdw *configDirectoryWatcher) close() {
	log.WithField(fieldConfigDir, cdw.path).Debug("Stopping config directory watcher")
	close(cdw.stop)
	cdw.watcher.Close()
}
