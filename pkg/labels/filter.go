// Copyright 2016-2017 Authors of Cilium
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

package labels

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// LPCfgFileVersion represents the version of a Label Prefix Configuration File
	LPCfgFileVersion = 1
)

// LabelPrefix is the cilium's representation of a container label.
type LabelPrefix struct {
	// Ignore if true will cause this prefix to be ignored insted of being accepted
	Ignore bool   `json:"invert"`
	Prefix string `json:"prefix"`
	Source string `json:"source"`
}

// String returns a human readable representation of the LabelPrefix
func (p LabelPrefix) String() string {
	s := fmt.Sprintf("%s:%s", p.Source, p.Prefix)
	if p.Ignore {
		s = "!" + s
	}

	return s
}

// Matches returns true if the label is matched by the LabelPrefix. The Ignore
// flag has no effect at this point.
func (p LabelPrefix) Matches(l *Label) bool {
	if p.Source != "" && p.Source != l.Source {
		return false
	}

	return strings.HasPrefix(l.Key, p.Prefix)
}

// parseLabelPrefix returns a LabelPrefix created from the string label parameter.
func parseLabelPrefix(label string) *LabelPrefix {
	labelPrefix := LabelPrefix{}
	t := strings.SplitN(label, ":", 2)
	if len(t) > 1 {
		labelPrefix.Source = t[0]
		labelPrefix.Prefix = t[1]
	} else {
		labelPrefix.Prefix = label
	}

	if labelPrefix.Prefix[0] == '!' {
		labelPrefix.Ignore = true
		labelPrefix.Prefix = labelPrefix.Prefix[1:]
	}

	return &labelPrefix
}

// ParseLabelPrefixCfg parses valid label prefixes from a file and from a slice
// of valid prefixes. Both are optional. If both are provided, both list are
// appended together.
func ParseLabelPrefixCfg(prefixes []string, file string) (*LabelPrefixCfg, error) {
	cfg, err := readLabelPrefixCfgFrom(file)
	if err != nil {
		return nil, fmt.Errorf("Unable to read label prefix file: %s\n", err)
	}

	for _, label := range prefixes {
		cfg.Append(parseLabelPrefix(label))
	}

	return cfg, nil
}

// LabelPrefixCfg is the label prefix configuration to filter labels of started
// containers.
type LabelPrefixCfg struct {
	Version       int            `json:"version"`
	LabelPrefixes []*LabelPrefix `json:"valid-prefixes"`
	// whitelist if true, indicates that an inclusive rule has to match
	// in order for the label to be considered
	whitelist bool
}

// Append adds an additional allowed label prefix to the configuration
func (cfg *LabelPrefixCfg) Append(l *LabelPrefix) {
	if !l.Ignore {
		cfg.whitelist = true
	}

	cfg.LabelPrefixes = append(cfg.LabelPrefixes, l)
}

// defaultLabelPrefixCfg returns a default LabelPrefixCfg using the latest
// LPCfgFileVersion
func defaultLabelPrefixCfg() *LabelPrefixCfg {
	return &LabelPrefixCfg{
		Version: LPCfgFileVersion,
		LabelPrefixes: []*LabelPrefix{
			{
				// Include namespace label
				Prefix: "io.kubernetes.pod.namespace",
			},
			{
				// Ignore all other labels
				Ignore: true,
				Prefix: "io.kubernetes",
			},
			{
				// Ignore all annotation.kubernete.io labels
				Ignore: true,
				Prefix: "annotation.kubernetes.io",
			},
			{
				// Ignore pod-template-hash
				Ignore: true,
				Prefix: "pod-template-hash",
			},
		},
	}
}

// readLabelPrefixCfgFrom reads a label prefix configuration file from fileName. If the
// version is not supported by us it returns an error.
func readLabelPrefixCfgFrom(fileName string) (*LabelPrefixCfg, error) {
	// if not file is specified, the default is empty
	if fileName == "" {
		return defaultLabelPrefixCfg(), nil
	}

	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lpc := LabelPrefixCfg{}
	err = json.NewDecoder(f).Decode(&lpc)
	if err != nil {
		return nil, err
	}
	if lpc.Version != LPCfgFileVersion {
		return nil, fmt.Errorf("unsupported version %d", lpc.Version)
	}
	for _, lp := range lpc.LabelPrefixes {
		if lp.Prefix == "" {
			return nil, fmt.Errorf("invalid label prefix file: prefix was empty")
		}
		if lp.Source == "" {
			return nil, fmt.Errorf("invalid label prefix file: source was empty")
		}
		if !lp.Ignore {
			lpc.whitelist = true
		}
	}
	return &lpc, nil
}

// FilterLabels returns Labels from the given labels that have the same source and the
// same prefix as one of lpc valid prefixes.
func (cfg *LabelPrefixCfg) FilterLabels(lbls Labels) Labels {
	filteredLabels := Labels{}
	for k, v := range lbls {
		included, ignored := 0, 0

		for _, p := range cfg.LabelPrefixes {
			if p.Matches(v) {
				if p.Ignore {
					// save length of shortest matching ignore
					if ignored == 0 || len(p.Prefix) < ignored {
						ignored = len(p.Prefix)
					}
				} else {
					// save length of longest matching include
					if len(p.Prefix) > included {
						included = len(p.Prefix)
					}
				}
			}
		}

		// A label is let through if it is:
		// - Included if at least one inclusive prefix is configured
		//   and not ignored with a longer or equal prefix length
		// - Not ignored if no inclusive prefix is configured
		if (!cfg.whitelist && ignored == 0) || included > ignored {
			// Just want to make sure we don't have labels deleted in
			// on side and disappearing in the other side...
			filteredLabels[k] = v.DeepCopy()
		}
	}
	return filteredLabels
}
