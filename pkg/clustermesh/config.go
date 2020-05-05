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

package clustermesh

import (
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// clusterLifecycle is the interface to implement in order to receive cluster
// configuration lifecycle events. This is implemented by the ClusterMesh.
type clusterLifecycle interface {
	add(clusterName, clusterConfigPath string)
	remove(clusterName string)
}

type configDirectoryWatcher struct {
	watcher   *fsnotify.Watcher
	lifecycle clusterLifecycle
	path      string
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
		lifecycle: lifecycle,
		stop:      make(chan struct{}),
	}, nil
}

func isEtcdConfigFile(path string) bool {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return false
	}

	// search for the "endpoints:" string
	return strings.Contains(string(b), "endpoints:")
}

func (cdw *configDirectoryWatcher) watch() error {
	log.WithField(fieldConfig, cdw.path).Debug("Starting config directory watcher")

	files, err := ioutil.ReadDir(cdw.path)
	if err != nil {
		return err
	}

	for _, f := range files {
		// A typical directory will look like this:
		// lrwxrwxrwx. 1 root root 12 Jul 21 16:32 test5 -> ..data/test5
		// lrwxrwxrwx. 1 root root 12 Jul 21 16:32 test7 -> ..data/test7
		//
		// Ignore all backing files and only read the symlinks
		if strings.HasPrefix(f.Name(), "..") || f.IsDir() {
			continue
		}

		absolutePath := path.Join(cdw.path, f.Name())
		if !isEtcdConfigFile(absolutePath) {
			continue
		}

		log.WithField(fieldClusterName, f.Name()).WithField("mode", f.Mode()).Debugf("Found configuration in initial scan")
		cdw.lifecycle.add(f.Name(), absolutePath)
	}

	go func() {
		for {
			select {
			case event := <-cdw.watcher.Events:
				name := filepath.Base(event.Name)
				log.WithField(fieldClusterName, name).Debugf("Received fsnotify event: %+v", event)
				switch event.Op {
				case fsnotify.Create, fsnotify.Write, fsnotify.Chmod:
					cdw.lifecycle.add(name, event.Name)
				case fsnotify.Remove, fsnotify.Rename:
					cdw.lifecycle.remove(name)
				}

			case err := <-cdw.watcher.Errors:
				log.WithError(err).WithField("path", cdw.path).Warning("error encountered while watching directory with fsnotify")

			case <-cdw.stop:
				return
			}
		}
	}()

	return nil
}

func (cdw *configDirectoryWatcher) close() {
	close(cdw.stop)
	cdw.watcher.Close()
}
