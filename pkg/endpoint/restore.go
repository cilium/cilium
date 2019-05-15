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
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
)

// deprecatedOptions represents the 'Opts' field in the Endpoint structure from
// Cilium 1.1 or earlier.
type deprecatedOptions struct {
	Opts map[string]bool `json:"map"`
}

// convertOptions handles backwards compatibility for the 'Opts' field.
//
// In Cilium 1.2, the ep.Opts became ep.Options and its internal storage type
// was converted from map[string]bool to map[string]int. To allow downgrade, we
// must populate the older Opts field based on the newer Options field.
//
// Consider deprecating in the Cilium 1.5 cycle or later.
func convertOptions(opts option.OptionMap) map[string]bool {
	result := make(map[string]bool, len(opts))
	for k, v := range opts {
		switch v {
		case option.OptionDisabled:
			result[k] = false
		case option.OptionEnabled:
			result[k] = true
		}
	}
	return result
}

// transformEndpointForDowngrade modifies the specified endpoint to populate
// deprecated fields so that when the endpoint is serialized, an older version
// of Cilium will understand the format. This allows safe downgrade from this
// version to an older version.
func transformEndpointForDowngrade(ep *Endpoint) {
	ep.DeprecatedOpts.Opts = convertOptions(ep.Options.Opts)
}

// ReadEPsFromDirNames returns a mapping of endpoint ID to endpoint of endpoints
// from a list of directory names that can possible contain an endpoint.
func ReadEPsFromDirNames(owner Owner, basePath string, eptsDirNames []string) map[uint16]*Endpoint {
	possibleEPs := map[uint16]*Endpoint{}
	for _, epDirName := range eptsDirNames {
		epDir := filepath.Join(basePath, epDirName)
		readDir := func() string {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.EndpointID: epDirName,
				logfields.Path:       filepath.Join(epDir, common.CHeaderFileName),
			})
			scopedLog.Debug("Reading directory")
			epFiles, err := ioutil.ReadDir(epDir)
			if err != nil {
				scopedLog.WithError(err).Warn("Error while reading directory. Ignoring it...")
				return ""
			}
			cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
			if cHeaderFile == "" {
				return ""
			}
			return cHeaderFile
		}
		// There's an odd issue where the first read dir doesn't work.
		cHeaderFile := readDir()
		if cHeaderFile == "" {
			cHeaderFile = readDir()
		}

		scopedLog := log.WithFields(logrus.Fields{
			logfields.EndpointID: epDirName,
			logfields.Path:       cHeaderFile,
		})

		if cHeaderFile == "" {
			scopedLog.Warning("C header file not found. Ignoring endpoint")
			continue
		}

		scopedLog.Debug("Found endpoint C header file")

		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := ParseEndpoint(owner.GetPolicyRepository(), strEp)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to parse the C header file")
			continue
		}
		if _, ok := possibleEPs[ep.ID]; ok {
			// If the endpoint already exists then give priority to the directory
			// that contains an endpoint that didn't fail to be build.
			if strings.HasSuffix(ep.DirectoryPath(), epDirName) {
				possibleEPs[ep.ID] = ep
			}
		} else {
			possibleEPs[ep.ID] = ep
		}
	}
	return possibleEPs
}
