// Copyright 2019 Google Inc. All Rights Reserved.
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

package licenses

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|README|NOTICE).*$`)
)

// FindCandidates returns the candidate file path of the license for this package.
//
// dir is path of the directory where we want to find a license.
// rootDir is path of the module containing this package. Find will not search out of the
// rootDir.
func FindCandidates(dir string, rootDir string) ([]string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	rootDir, err = filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(dir, rootDir) {
		return nil, fmt.Errorf("licenses.Find: rootDir %s should contain dir %s", rootDir, dir)
	}

	return findAllUpwards(dir, licenseRegexp, rootDir)
}

func findAllUpwards(dir string, r *regexp.Regexp, stopAt string) ([]string, error) {
	var foundPaths []string

	// Stop once we go out of the stopAt dir.
	for strings.HasPrefix(dir, stopAt) {
		dirContents, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}

		for _, f := range dirContents {
			if f.IsDir() {
				continue
			}

			if r.MatchString(f.Name()) {
				path := filepath.Join(dir, f.Name())
				foundPaths = append(foundPaths, path)
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Can't go any higher up the directory tree.
			break
		}
		dir = parent
	}

	return foundPaths, nil
}
