// Copyright 2022 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package assets

import (
	"embed"
	"io/fs"
	"strings"

	classifier "github.com/google/licenseclassifier/v2"
)

//go:embed */*/*
var licenseFS embed.FS

// DefaultClassifier returns a classifier loaded with the contents of the
// assets directory.
func DefaultClassifier() (*classifier.Classifier, error) {
	c := classifier.NewClassifier(.8)

	err := fs.WalkDir(licenseFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		b, err := licenseFS.ReadFile(path)
		if err != nil {
			return err
		}
		splits := strings.Split(path, "/")
		category, name, variant := splits[0], splits[1], splits[2]
		c.AddContent(category, name, variant, b)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return c, nil

}

// ReadLicenseFile locates and reads the license archive file.  Absolute paths are used unmodified.  Relative paths are expected to be in the licenses directory of the licenseclassifier package.
func ReadLicenseFile(filename string) ([]byte, error) {
	return licenseFS.ReadFile(filename)
}

// ReadLicenseDir reads directory containing the license files.
func ReadLicenseDir() ([]fs.DirEntry, error) {
	return licenseFS.ReadDir(".")
}
