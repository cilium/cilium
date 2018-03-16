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
	"regexp"
	"strings"

	"github.com/cilium/cilium/common"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
)

var (
	log                  = logging.DefaultLogger
	validLabelPrefixesMU lock.RWMutex
	validLabelPrefixes   *labelPrefixCfg // Label prefixes used to filter from all labels
)

const (
	// LPCfgFileVersion represents the version of a Label Prefix Configuration File
	LPCfgFileVersion = 1
)

// LabelPrefix is the cilium's representation of a container label.
// +k8s:deepcopy-gen=false
// +k8s:openapi-gen=false
type LabelPrefix struct {
	// Ignore if true will cause this prefix to be ignored insted of being accepted
	Ignore bool   `json:"invert"`
	Prefix string `json:"prefix"`
	Source string `json:"source"`
	expr   *regexp.Regexp
}

// String returns a human readable representation of the LabelPrefix
func (p LabelPrefix) String() string {
	s := fmt.Sprintf("%s:%s", p.Source, p.Prefix)
	if p.Ignore {
		s = "!" + s
	}

	return s
}

// matches returns true and the length of the matched section if the label is
// matched by the LabelPrefix. The Ignore flag has no effect at this point.
func (p LabelPrefix) matches(l *Label) (bool, int) {
	if p.Source != "" && p.Source != l.Source {
		return false, 0
	}

	// If no regular expression is available, fall back to prefix matching
	if p.expr == nil {
		return strings.HasPrefix(l.Key, p.Prefix), len(p.Prefix)
	}

	res := p.expr.FindStringIndex(l.Key)

	// No match if regexp was not found
	if res == nil {
		return false, 0
	}

	// Otherwise match if match was found at start of key
	return res[0] == 0, res[1]
}

// parseLabelPrefix returns a LabelPrefix created from the string label parameter.
func parseLabelPrefix(label string) (*LabelPrefix, error) {
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

	r, err := regexp.Compile(labelPrefix.Prefix)
	if err != nil {
		return nil, fmt.Errorf("Unable to compile regexp: %s", err)
	}
	labelPrefix.expr = r

	return &labelPrefix, nil
}

// ParseLabelPrefixCfg parses valid label prefixes from a file and from a slice
// of valid prefixes. Both are optional. If both are provided, both list are
// appended together.
func ParseLabelPrefixCfg(prefixes []string, file string) error {
	cfg, err := readLabelPrefixCfgFrom(file)
	if err != nil {
		return fmt.Errorf("Unable to read label prefix file: %s", err)
	}

	for _, label := range prefixes {
		p, err := parseLabelPrefix(label)
		if err != nil {
			return err
		}

		if !p.Ignore {
			cfg.whitelist = true
		}

		cfg.LabelPrefixes = append(cfg.LabelPrefixes, p)
	}

	validLabelPrefixes = cfg

	log.Info("Valid label prefix configuration:")
	for _, l := range validLabelPrefixes.LabelPrefixes {
		log.Infof(" - %s", l)
	}

	return nil
}

// labelPrefixCfg is the label prefix configuration to filter labels of started
// containers.
// +k8s:openapi-gen=false
type labelPrefixCfg struct {
	Version       int            `json:"version"`
	LabelPrefixes []*LabelPrefix `json:"valid-prefixes"`
	// whitelist if true, indicates that an inclusive rule has to match
	// in order for the label to be considered
	whitelist bool
}

// defaultLabelPrefixCfg returns a default LabelPrefixCfg using the latest
// LPCfgFileVersion
func defaultLabelPrefixCfg() *labelPrefixCfg {
	cfg := &labelPrefixCfg{
		Version:       LPCfgFileVersion,
		LabelPrefixes: []*LabelPrefix{},
	}

	expressions := []string{
		k8sConst.PodNamespaceLabel,                                 // include io.kubernetes.pod.namspace
		k8sConst.PodNamespaceMetaLabels,                            // include all namespace labels
		"!io.kubernetes",                                           // ignore all other io.kubernetes labels
		"!.*kubernetes.io",                                         // ignore all other kubernetes.io labels (annotation.*.k8s.io)
		"!pod-template-generation",                                 // ignore pod-template-generation
		"!pod-template-hash",                                       // ignore pod-template-hash
		"!controller-revision-hash",                                // ignore controller-revision-hash
		"!annotation." + common.CiliumK8sAnnotationPrefix,          // ignore all cilium annotations
		"!annotation." + common.CiliumIdentityAnnotationDeprecated, // ignore all cilium annotations
	}

	for _, e := range expressions {
		p, err := parseLabelPrefix(e)
		if err != nil {
			msg := fmt.Sprintf("BUG: Unable to parse default label prefix '%s': %s", e, err)
			panic(msg)
		}
		cfg.LabelPrefixes = append(cfg.LabelPrefixes, p)
	}

	return cfg
}

// readLabelPrefixCfgFrom reads a label prefix configuration file from fileName. If the
// version is not supported by us it returns an error.
func readLabelPrefixCfgFrom(fileName string) (*labelPrefixCfg, error) {
	// if not file is specified, the default is empty
	if fileName == "" {
		return defaultLabelPrefixCfg(), nil
	}

	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lpc := labelPrefixCfg{}
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

func (cfg *labelPrefixCfg) filterLabels(lbls Labels) (identityLabels, informationLabels Labels) {
	validLabelPrefixesMU.RLock()
	defer validLabelPrefixesMU.RUnlock()

	identityLabels = Labels{}
	informationLabels = Labels{}
	for k, v := range lbls {
		included, ignored := 0, 0

		for _, p := range cfg.LabelPrefixes {
			if m, len := p.matches(v); m {
				if p.Ignore {
					// save length of shortest matching ignore
					if ignored == 0 || len < ignored {
						ignored = len
					}
				} else {
					// save length of longest matching include
					if len > included {
						included = len
					}
				}
			}
		}

		// A label is accepted if :
		// - No inclusive LabelPrefix (Ignore flag not set) is
		//   configured and label is not ignored.
		// - An inclusive LabelPrefix matches the label
		// - If both an inclusive and ignore LabelPrefix match, the
		//   label is accepted if the matching section in the label
		//   is greater than the ignored matching section in label,
		//   e.g. when evaluating the label foo.bar, the prefix rules
		//   {!foo, foo.bar} will cause the label to be accepted
		//   because the inclusive prefix matches over a longer section.
		if (!cfg.whitelist && ignored == 0) || included > ignored {
			// Just want to make sure we don't have labels deleted in
			// on side and disappearing in the other side...
			identityLabels[k] = v.DeepCopy()
		} else {
			informationLabels[k] = v.DeepCopy()
		}
	}
	return identityLabels, informationLabels
}

// FilterLabels returns Labels from the given labels that have the same source and the
// same prefix as one of lpc valid prefixes, as well as labels that do not match
// the aforementioned filtering criteria.
func FilterLabels(lbls Labels) (identityLabels, informationLabels Labels) {
	return validLabelPrefixes.filterLabels(lbls)
}
