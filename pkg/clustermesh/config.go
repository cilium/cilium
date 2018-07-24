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

type clusterLifecycle interface {
	add(name, path string)
	remove(name string)
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
		stop:      make(chan struct{}, 0),
	}, nil
}

func (cdw *configDirectoryWatcher) watch() error {
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
		if strings.HasPrefix(f.Name(), "..") {
			continue
		}

		log.WithField("name", f.Name()).WithField("mode", f.Mode()).Debugf("Found configuration in initial scan")
		cdw.lifecycle.add(f.Name(), path.Join(cdw.path, f.Name()))
	}

	for {
		select {
		case event := <-cdw.watcher.Events:
			name := filepath.Base(event.Name)
			log.WithField("name", name).Debugf("Received fsnotify event: %+v", event)
			switch event.Op {
			case fsnotify.Create, fsnotify.Write, fsnotify.Chmod:
				cdw.lifecycle.add(name, event.Name)
			case fsnotify.Remove, fsnotify.Rename:
				cdw.lifecycle.remove(name)
			}

		case err := <-cdw.watcher.Errors:
			return err

		case <-cdw.stop:
			return nil
		}
	}
}

func (cdw *configDirectoryWatcher) close() {
	close(cdw.stop)
	cdw.watcher.Close()
}
