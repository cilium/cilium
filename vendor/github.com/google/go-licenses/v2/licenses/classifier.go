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
	"os"

	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
)

// Classifier can detect the type of a software license.
type Classifier interface {
	Identify(licensePath string) ([]License, error)
}

type googleClassifier struct {
	classifier *licenseclassifier.Classifier
}

// NewClassifier creates a classifier
func NewClassifier() (Classifier, error) {
	c, err := assets.DefaultClassifier()
	if err != nil {
		return nil, err
	}
	return &googleClassifier{classifier: c}, nil
}

type License struct {
	Name string
	Type Type
}

// Identify returns the name and type of a license, given its file path.
// An empty license path results in an empty name and Unknown type.
func (c *googleClassifier) Identify(licensePath string) ([]License, error) {
	if licensePath == "" {
		return nil, nil
	}

	file, err := os.Open(licensePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	matches, err := c.classifier.MatchFrom(file)
	if err != nil {
		return nil, err
	}

	foundLicenseNames := map[string]struct{}{}

	licenses := []License{}
	for _, match := range matches.Matches {
		if match.MatchType != "License" {
			continue
		}

		// Skip duplicate licenses.
		if _, ok := foundLicenseNames[match.Name]; ok {
			continue
		}
		foundLicenseNames[match.Name] = struct{}{}

		licenses = append(licenses, License{
			Name: match.Name,
			Type: LicenseType(match.Name),
		})
	}

	return licenses, nil
}
