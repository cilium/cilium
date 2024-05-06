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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|README|NOTICE).*$`)
)

// Find returns the file path of the license for this package.
//
// dir is path of the directory where we want to find a license.
// rootDir is path of the module containing this package. Find will not search out of the
// rootDir.
func Find(dir string, rootDir string, classifier Classifier) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	rootDir, err = filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(dir, rootDir) {
		return "", fmt.Errorf("licenses.Find: rootDir %s should contain dir %s", rootDir, dir)
	}
	found, err := findUpwards(dir, licenseRegexp, rootDir, func(path string) bool {
		// TODO(RJPercival): Return license details
		if _, _, err := classifier.Identify(path); err != nil {
			return false
		}
		return true
	})
	if err != nil {
		if errors.Is(err, errNotFound) {
			return "", fmt.Errorf("cannot find a known open source license for %q whose name matches regexp %s and locates up until %q", dir, licenseRegexp, rootDir)
		}
		return "", fmt.Errorf("finding a known open source license: %w", err)
	}
	return found, nil
}

var errNotFound = fmt.Errorf("file/directory matching predicate and regexp not found")

func findUpwards(dir string, r *regexp.Regexp, stopAt string, predicate func(path string) bool) (string, error) {
	// Dir must be made absolute for reliable matching with stopAt regexps
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	start := dir
	// Stop once we go out of the stopAt dir.
	for strings.HasPrefix(dir, stopAt) {
		dirContents, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		for _, f := range dirContents {
			if r.MatchString(f.Name()) {
				path := filepath.Join(dir, f.Name())
				if predicate != nil && !predicate(path) {
					continue
				}
				return path, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Can't go any higher up the directory tree.
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("findUpwards(dir=%q, regexp=%q, stopAt=%q, predicate=func): %w", start, r, stopAt, errNotFound)
}
