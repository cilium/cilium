// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilter

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log                  = logging.DefaultLogger.WithField(logfields.LogSubsys, "labels-filter")
	validLabelPrefixesMU lock.RWMutex
	validLabelPrefixes   *labelPrefixCfg // Label prefixes used to filter from all labels
)

const (
	// LPCfgFileVersion represents the version of a Label Prefix Configuration File
	LPCfgFileVersion = 1

	// reservedLabelsPattern is the prefix pattern for all reserved labels
	reservedLabelsPattern = labels.LabelSourceReserved + ":.*"
)

// LabelPrefix is the cilium's representation of a container label.
// +k8s:deepcopy-gen=false
// +k8s:openapi-gen=false
// +deepequal-gen=false
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
func (p LabelPrefix) matches(l labels.Label) (bool, int) {
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
	i := strings.IndexByte(label, ':')
	if i >= 0 {
		labelPrefix.Source = label[:i]
		labelPrefix.Prefix = label[i+1:]
	} else {
		labelPrefix.Prefix = label
	}

	if len(labelPrefix.Prefix) == 0 {
		return nil, fmt.Errorf("invalid label source %q, prefix %q",
			labelPrefix.Source, labelPrefix.Prefix)
	}
	if labelPrefix.Prefix[0] == '!' {
		labelPrefix.Ignore = true
		labelPrefix.Prefix = labelPrefix.Prefix[1:]
	}

	r, err := regexp.Compile(labelPrefix.Prefix)
	if err != nil {
		return nil, fmt.Errorf("unable to compile regexp: %s", err)
	}
	labelPrefix.expr = r

	return &labelPrefix, nil
}

// ParseLabelPrefixCfg parses valid label prefixes from a file and from a slice
// of valid prefixes. Both are optional. If both are provided, both list are
// appended together.
func ParseLabelPrefixCfg(prefixes []string, file string) error {
	var cfg *labelPrefixCfg
	var err error
	var fromCustomFile bool

	// Use default label prefix if configuration file not provided
	if file == "" {
		log.Info("Parsing base label prefixes from default label list")
		cfg = defaultLabelPrefixCfg()
	} else {
		log.Infof("Parsing base label prefixes from file %s", file)
		cfg, err = readLabelPrefixCfgFrom(file)
		if err != nil {
			return fmt.Errorf("unable to read label prefix file: %s", err)
		}

		fromCustomFile = true
	}

	log.Infof("Parsing additional label prefixes from user inputs: %v", prefixes)
	for _, label := range prefixes {
		if len(label) == 0 {
			continue
		}
		p, err := parseLabelPrefix(label)
		if err != nil {
			return err
		}

		if !p.Ignore {
			cfg.whitelist = true
		}

		cfg.LabelPrefixes = append(cfg.LabelPrefixes, p)
	}

	if fromCustomFile {
		found := false
		for _, label := range cfg.LabelPrefixes {
			if label.Source+":"+label.Prefix == reservedLabelsPattern {
				found = true
				break
			}
		}

		if !found {
			log.Errorf("'%s' needs to be included in the final label list for "+
				"Cilium to work properly.", reservedLabelsPattern)
		}
	}

	validLabelPrefixes = cfg

	log.Info("Final label prefixes to be used for identity evaluation:")
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
		reservedLabelsPattern,                             // include all reserved labels
		regexp.QuoteMeta(k8sConst.PodNamespaceLabel),      // include io.kubernetes.pod.namespace
		regexp.QuoteMeta(k8sConst.PodNamespaceMetaLabels), // include all namespace labels
		regexp.QuoteMeta(k8sConst.AppKubernetes),          // include app.kubernetes.io
		`!io\.kubernetes`,                                 // ignore all other io.kubernetes labels
		`!kubernetes\.io`,                                 // ignore all other kubernetes.io labels
		`!.*beta\.kubernetes\.io`,                         // ignore all beta.kubernetes.io labels
		`!k8s\.io`,                                        // ignore all k8s.io labels
		`!pod-template-generation`,                        // ignore pod-template-generation
		`!pod-template-hash`,                              // ignore pod-template-hash
		`!controller-revision-hash`,                       // ignore controller-revision-hash
		`!annotation.*`,                                   // ignore all annotation labels
		`!etcd_node`,                                      // ignore etcd_node label
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

// readLabelPrefixCfgFrom reads a label prefix configuration file from fileName.
// return an error if fileName is empty, or if version is not supported.
func readLabelPrefixCfgFrom(fileName string) (*labelPrefixCfg, error) {
	if fileName == "" {
		return nil, fmt.Errorf("label prefix file not provided")
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

func (cfg *labelPrefixCfg) filterLabels(lbls labels.Labels) (identityLabels, informationLabels labels.Labels) {
	if len(lbls) == 0 {
		return nil, nil
	}

	validLabelPrefixesMU.RLock()
	defer validLabelPrefixesMU.RUnlock()

	identityLabels = labels.Labels{}
	informationLabels = labels.Labels{}
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
			identityLabels[k] = v
		} else {
			informationLabels[k] = v
		}
	}
	return identityLabels, informationLabels
}

// Filter returns Labels from the given labels that have the same source and the
// same prefix as one of lpc valid prefixes, as well as labels that do not match
// the aforementioned filtering criteria.
func Filter(lbls labels.Labels) (identityLabels, informationLabels labels.Labels) {
	return validLabelPrefixes.filterLabels(lbls)
}
