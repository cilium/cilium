// Copyright 2017 Google Inc.
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

package licenseclassifier

import (
	"github.com/google/licenseclassifier/licenses"
)

const (
	// LicenseArchive is the name of the archive containing preprocessed
	// license texts.
	LicenseArchive = "licenses.db"
	// ForbiddenLicenseArchive is the name of the archive containing preprocessed
	// forbidden license texts only.
	ForbiddenLicenseArchive = "forbidden_licenses.db"
)

// ReadLicenseFile locates and reads the license archive file.  Absolute paths are used unmodified.  Relative paths are expected to be in the licenses directory of the licenseclassifier package.
var ReadLicenseFile = licenses.ReadLicenseFile

// ReadLicenseDir reads directory containing the license files.
var ReadLicenseDir = licenses.ReadLicenseDir
