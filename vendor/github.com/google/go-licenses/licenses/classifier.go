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

	"github.com/google/licenseclassifier"
)

// Type identifies a class of software license.
type Type string

// License types
const (
	// Unknown license type.
	Unknown = Type("")
	// Restricted licenses require mandatory source distribution if we ship a
	// product that includes third-party code protected by such a license.
	Restricted = Type("restricted")
	// Reciprocal licenses allow usage of software made available under such
	// licenses freely in *unmodified* form. If the third-party source code is
	// modified in any way these modifications to the original third-party
	// source code must be made available.
	Reciprocal = Type("reciprocal")
	// Notice licenses contain few restrictions, allowing original or modified
	// third-party software to be shipped in any product without endangering or
	// encumbering our source code. All of the licenses in this category do,
	// however, have an "original Copyright notice" or "advertising clause",
	// wherein any external distributions must include the notice or clause
	// specified in the license.
	Notice = Type("notice")
	// Permissive licenses are even more lenient than a 'notice' license.
	// Not even a copyright notice is required for license compliance.
	Permissive = Type("permissive")
	// Unencumbered covers licenses that basically declare that the code is "free for any use".
	Unencumbered = Type("unencumbered")
	// Forbidden licenses are forbidden to be used.
	Forbidden = Type("FORBIDDEN")
)

func (t Type) String() string {
	switch t {
	case Unknown:
		// licenseclassifier uses an empty string to indicate an unknown license
		// type, which is unclear to users when printed as a string.
		return "unknown"
	default:
		return string(t)
	}
}

// Classifier can detect the type of a software license.
type Classifier interface {
	Identify(licensePath string) (string, Type, error)
}

type googleClassifier struct {
	classifier *licenseclassifier.License
}

// NewClassifier creates a classifier that requires a specified confidence threshold
// in order to return a positive license classification.
func NewClassifier(confidenceThreshold float64) (Classifier, error) {
	c, err := licenseclassifier.New(confidenceThreshold)
	if err != nil {
		return nil, err
	}
	return &googleClassifier{classifier: c}, nil
}

// Identify returns the name and type of a license, given its file path.
// An empty license path results in an empty name and Unknown type.
func (c *googleClassifier) Identify(licensePath string) (string, Type, error) {
	if licensePath == "" {
		return "", Unknown, nil
	}
	content, err := os.ReadFile(licensePath)
	if err != nil {
		return "", "", err
	}
	matches := c.classifier.MultipleMatch(string(content), true)
	if len(matches) == 0 {
		return "", "", fmt.Errorf("unknown license")
	}
	licenseName := matches[0].Name
	return licenseName, Type(licenseclassifier.LicenseType(licenseName)), nil
}
