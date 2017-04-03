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

	"github.com/cilium/cilium/common"
)

const (
	// LPCfgFileVersion represents the version of a Label Prefix Configuration File
	LPCfgFileVersion = 1
)

// LabelPrefix is the cilium's representation of a container label.
type LabelPrefix struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
}

func (p LabelPrefix) String() string {
	return fmt.Sprintf("%s:%s", p.Source, p.Prefix)
}

// ParseLabelPrefix returns a LabelPrefix created from the string label parameter.
func ParseLabelPrefix(label string) *LabelPrefix {
	labelPrefix := LabelPrefix{}
	t := strings.SplitN(label, ":", 2)
	if len(t) > 1 {
		labelPrefix.Source = t[0]
		labelPrefix.Prefix = t[1]
	} else {
		labelPrefix.Prefix = label
	}

	return &labelPrefix
}

// LabelPrefixCfg is the label prefix configuration to filter labels of started
// containers.
type LabelPrefixCfg struct {
	Version       int            `json:"version"`
	LabelPrefixes []*LabelPrefix `json:"valid-prefixes"`
}

// Append adds an additional allowed label prefix to the configuration
func (cfg *LabelPrefixCfg) Append(l *LabelPrefix) {
	cfg.LabelPrefixes = append(cfg.LabelPrefixes, l)
}

// DefaultLabelPrefixCfg returns a default LabelPrefixCfg using the latest
// LPCfgFileVersion
func DefaultLabelPrefixCfg() *LabelPrefixCfg {
	return &LabelPrefixCfg{
		Version: LPCfgFileVersion,
		LabelPrefixes: []*LabelPrefix{
			{
				Prefix: "id.",
			},
			{
				Prefix: "io.cilium.",
			},
			{
				Prefix: common.K8sPodNamespaceLabel,
				Source: common.K8sLabelSource,
			},
		},
	}
}

// DefaultK8sLabelPrefixCfg returns a default LabelPrefixCfg using the latest
// LPCfgFileVersion and the following label prefixes: Key: "k8s-app", Source:
// common.K8sLabelSource and Key: "version", Source: common.K8sLabelSource.
func DefaultK8sLabelPrefixCfg() *LabelPrefixCfg {
	return &LabelPrefixCfg{
		Version: LPCfgFileVersion,
		LabelPrefixes: []*LabelPrefix{
			{
				Prefix: "k8s-app",
				Source: common.K8sLabelSource,
			},
			{
				Prefix: "version",
				Source: common.K8sLabelSource,
			},
		},
	}
}

// ReadLabelPrefixCfgFrom reads a label prefix configuration file from fileName. If the
// version is not supported by us it returns an error.
func ReadLabelPrefixCfgFrom(fileName string) (*LabelPrefixCfg, error) {
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
	}
	return &lpc, nil
}

// FilterLabels returns Labels from the given labels that have the same source and the
// same prefix as one of lpc valid prefixes.
func (cfg *LabelPrefixCfg) FilterLabels(lbls Labels) Labels {
	filteredLabels := Labels{}
	for k, v := range lbls {
		for _, lpcValue := range cfg.LabelPrefixes {
			if lpcValue.Source != "" && lpcValue.Source != v.Source {
				continue
			}

			if strings.HasPrefix(v.Key, lpcValue.Prefix) {
				// Just want to make sure we don't have labels deleted in
				// on side and disappearing in the other side...
				filteredLabels[k] = v.DeepCopy()
			}
		}
	}
	return filteredLabels
}
