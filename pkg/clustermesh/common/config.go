// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Config struct {
	// ClusterMeshConfig is the path to the clustermesh configuration directory.
	ClusterMeshConfig string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("clustermesh-config", def.ClusterMeshConfig, "Path to the ClusterMesh configuration directory")
}

var DefaultConfig = Config{
	ClusterMeshConfig: "",
}

// clusterLifecycle is the interface to implement in order to receive cluster
// configuration lifecycle events. This is implemented by the ClusterMesh.
type clusterLifecycle interface {
	add(clusterName, clusterConfigPath string)
	remove(clusterName string)
}

type fhash [sha256.Size]byte

type configDirectoryWatcher struct {
	logger *slog.Logger
	// Use two separate watchers, one for the directory itself, and one for the
	// individual config files. We need to explicitly watch the config files
	// to receive a notification when the underlying file gets updated, if the
	// path points to a symbolic link. Additionally, we need to use two separate
	// watchers to ensure receiving the remove event when the symbolic link
	// starts pointing to a different file (hence breaking the existing watcher),
	// so that we can re-establish it. Indeed, the fsnotify library does no longer
	// propagate that event when the parent directory is also watched, to prevent
	// a duplicate event, which doesn't get emitted in this case though.
	// Related: fsnotify/fsnotify#620
	watcher    *fsnotify.Watcher
	cfgWatcher *fsnotify.Watcher
	lifecycle  clusterLifecycle
	path       string
	tracked    map[string]fhash
	stop       chan struct{}
}

func createConfigDirectoryWatcher(logger *slog.Logger, path string, lifecycle clusterLifecycle) (*configDirectoryWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	cfgWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		cfgWatcher.Close()
		return nil, err
	}

	return &configDirectoryWatcher{
		logger:     logger,
		watcher:    watcher,
		cfgWatcher: cfgWatcher,
		path:       path,
		tracked:    map[string]fhash{},
		lifecycle:  lifecycle,
		stop:       make(chan struct{}),
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
	filename := filepath.Base(abspath)
	isConfig, newHash := isEtcdConfigFile(abspath)

	if !isConfig {
		// If the corresponding cluster was tracked, then trigger the remove
		// event, since the configuration file is no longer present/readable
		if _, tracked := cdw.tracked[filename]; tracked {
			cdw.logger.Debug(
				"Removed cluster configuration",
				fieldClusterName, filename,
				fieldConfig, abspath,
			)

			// The remove operation returns an error if the file does no longer exists.
			_ = cdw.cfgWatcher.Remove(abspath)
			delete(cdw.tracked, filename)
			cdw.lifecycle.remove(filename)
		}

		return
	}

	if !slices.Contains(cdw.cfgWatcher.WatchList(), abspath) {
		// Start watching explicitly the file. This allows to receive a notification
		// when the underlying file gets updated, if path points to a symbolic link.
		// This is required to correctly detect file modifications when the folder
		// is mounted from a Kubernetes ConfigMap/Secret.
		if err := cdw.cfgWatcher.Add(abspath); err != nil && !errors.Is(err, os.ErrNotExist) {
			cdw.logger.Warn(
				"Failed adding explicit path watch for config",
				logfields.Error, err,
				fieldConfig, abspath,
			)
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
			return
		}
	}

	oldHash, tracked := cdw.tracked[filename]

	// Do not emit spurious notifications if the config file did not change.
	if tracked && oldHash == newHash {
		return
	}

	cdw.logger.Debug(
		"Added or updated cluster configuration",
		fieldClusterName, filename,
		fieldConfig, abspath,
	)

	cdw.tracked[filename] = newHash
	cdw.lifecycle.add(filename, abspath)
}

func (cdw *configDirectoryWatcher) watch() error {
	cdw.logger.Debug(
		"Starting config directory watcher",
		fieldConfigDir, cdw.path,
	)

	files, err := os.ReadDir(cdw.path)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		absolutePath := filepath.Join(cdw.path, f.Name())
		cdw.handle(absolutePath)
	}

	go cdw.loop()
	return nil
}

func (cdw *configDirectoryWatcher) loop() {
	handle := func(event fsnotify.Event) {
		cdw.logger.Debug(
			"Received fsnotify event",
			fieldConfigDir, cdw.path,
			fieldEvent, event,
		)
		cdw.handle(event.Name)
	}

	for {
		select {
		case event := <-cdw.watcher.Events:
			handle(event)

		case event := <-cdw.cfgWatcher.Events:
			handle(event)

		case err := <-cdw.watcher.Errors:
			cdw.logger.Warn(
				"Error encountered while watching directory with fsnotify",
				logfields.Error, err,
				fieldConfigDir, cdw.path,
			)

		case err := <-cdw.cfgWatcher.Errors:
			cdw.logger.Warn(
				"Error encountered while watching individual configuration with fsnotify",
				logfields.Error, err,
				fieldConfigDir, cdw.path,
			)

		case <-cdw.stop:
			return
		}
	}
}

func (cdw *configDirectoryWatcher) close() {
	cdw.logger.Debug(
		"Stopping config directory watcher",
		fieldConfigDir, cdw.path,
	)
	close(cdw.stop)
	cdw.watcher.Close()
	cdw.cfgWatcher.Close()
}

// ConfigFiles returns the list of configuration files in the given path. It
// shall be used by CLI tools only, as it doesn't handle subsequent updates.
func ConfigFiles(cfgdir string) (configs map[string]string, err error) {
	files, err := os.ReadDir(cfgdir)
	if err != nil {
		return nil, err
	}

	configs = make(map[string]string)
	for _, f := range files {
		cfgfile := filepath.Join(cfgdir, f.Name())
		if ok, _ := isEtcdConfigFile(cfgfile); ok {
			configs[f.Name()] = cfgfile
		}
	}

	return configs, nil
}
