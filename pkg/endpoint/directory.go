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
	"strconv"
)

func (e *Endpoint) directoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

// FilterEPDir returns a list of directories' names that possible belong to an endpoint.
func FilterEPDir(dirFiles []os.FileInfo) []string {
	eptsID := []string{}
	for _, file := range dirFiles {
		if file.IsDir() {
			if _, err := strconv.ParseUint(file.Name(), 10, 16); err == nil {
				eptsID = append(eptsID, file.Name())
			}
		}
	}
	return eptsID
}

func (e *Endpoint) removeDirectory() {
	os.RemoveAll(e.directoryPath())
}

func (e *Endpoint) RemoveDirectory() {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	e.removeDirectory()
}

func (e *Endpoint) CreateDirectory() error {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	lxcDir := e.directoryPath()
	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		return fmt.Errorf("unable to create endpoint directory: %s", err)
	}

	return nil
}
