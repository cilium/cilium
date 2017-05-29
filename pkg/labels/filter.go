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

	"github.com/cilium/cilium/pkg/k8s"
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
	// whitelist if true, indicates that at least one non-ignore prefix
	// rule is present
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
		Version:   LPCfgFileVersion,
		whitelist: true,
		LabelPrefixes: []*LabelPrefix{
			{
				Prefix: "id.",
			},
			{
				Prefix: "io.cilium.",
			},
			{
				Prefix: k8s.PodNamespaceLabel,
				Source: k8s.LabelSource,
			},
		},
	}
}

// DefaultK8sLabelPrefixCfg returns a default LabelPrefixCfg using the latest
// LPCfgFileVersion and the following label prefixes: Key: "k8s-app", Source:
// k8s.K8sLabelSource and Key: "version", Source: k8s.K8sLabelSource.
func DefaultK8sLabelPrefixCfg() *LabelPrefixCfg {
	return &LabelPrefixCfg{
		Version: LPCfgFileVersion,
		LabelPrefixes: []*LabelPrefix{
			{
				Prefix: "k8s-app",
				Source: k8s.LabelSource,
			},
			{
				Prefix: "version",
				Source: k8s.LabelSource,
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
		included, ignored := false, false

		for _, p := range cfg.LabelPrefixes {
			if p.Matches(v) {
				if p.Ignore {
					ignored = true
				} else {
					included = true
				}
			}
		}

		// A label is let through if it is:
		// - Not ignored
		// - Explicitely listed
		// - Not listed but no prefix has been whitelisted and thus all
		//   prefixes are included except those ignored
		if (!cfg.whitelist || included) && !ignored {
			// Just want to make sure we don't have labels deleted in
			// on side and disappearing in the other side...
			filteredLabels[k] = v.DeepCopy()
		}
	}
	return filteredLabels
}
