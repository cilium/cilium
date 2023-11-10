// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
)

func sourceLabels(ev *v1.Event) k8sLabels.Labels {
	labels := ev.GetFlow().GetSource().GetLabels()
	return ciliumLabels.ParseLabelArrayFromArray(labels)
}

func destinationLabels(ev *v1.Event) k8sLabels.Labels {
	labels := ev.GetFlow().GetDestination().GetLabels()
	return ciliumLabels.ParseLabelArrayFromArray(labels)
}

var (
	labelSelectorWithColon = regexp.MustCompile(`([^,]\s*[a-z0-9-]+):([a-z0-9-]+)`)
)

func translateKey(ckey string) string {
	if !strings.Contains(ckey, ":") {
		return fmt.Sprintf("any.%s", ckey)
	}
	return strings.Replace(ckey, ":", ".", 1)
}

func translateSelector(selector string) string {
	translated := strings.Builder{}

	nesting := 0
	preKey := true
	parsingKey := false
	key := strings.Builder{}
	for _, r := range selector {
		if preKey {
			switch {
			case unicode.IsSpace(r) || r == '!':
				translated.WriteRune(r)
			default:
				preKey = false
				parsingKey = true
			}
		}
		if parsingKey {
			switch {
			default:
				key.WriteRune(r)
			case unicode.IsSpace(r) || r == '=' || r == '!' || r == ',':
				translated.WriteString(translateKey(key.String()))
				key = strings.Builder{}
				parsingKey = false
			}
		}
		if !parsingKey && !preKey {
			switch {
			case r == ',' && nesting == 0:
				preKey = true
			case r == '(':
				nesting++
			case r == ')':
				nesting--
			default:
			}
			translated.WriteRune(r)
		}
	}
	if parsingKey {
		translated.WriteString(translateKey(key.String()))
	}

	return translated.String()
}

func parseSelector(selector string) (k8sLabels.Selector, error) {
	// ciliumLabels.LabelArray extends the k8sLabels.Selector logic with
	// support for Cilium source prefixes such as "k8s:foo" or "any:bar".
	// It does this by treating the string before the first dot as the source
	// prefix, i.e. `k8s.foo` is treated like `k8s:foo`. This translation is
	// needed because k8sLabels.Selector does not support colons in label names.
	//
	// We do not want to expose this implementation detail to the user,
	// therefore we translate any user-specified source prefixes by
	// replacing colon-based source prefixes in labels with dot-based prefixes,
	// i.e. "k8s:foo in (bar, baz)" becomes "k8s.foo in (bar, baz)".

	translated := translateSelector(selector)
	return k8sLabels.Parse(translated)
}

// FilterByLabelSelectors returns a FilterFunc. The FilterFunc returns true if and only if any of the
// specified selectors select the event. The caller specifies how to extract labels from the event.
func FilterByLabelSelectors(labelSelectors []string, getLabels func(*v1.Event) k8sLabels.Labels) (FilterFunc, error) {
	selectors := make([]k8sLabels.Selector, 0, len(labelSelectors))
	for _, selector := range labelSelectors {
		s, err := parseSelector(selector)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, s)
	}

	return func(ev *v1.Event) bool {
		labels := getLabels(ev)
		for _, selector := range selectors {
			if selector.Matches(labels) {
				return true
			}
		}
		return false
	}, nil
}

// LabelsFilter implements filtering based on labels
type LabelsFilter struct{}

// OnBuildFilter builds a labels filter
func (l *LabelsFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourceLabel() != nil {
		slf, err := FilterByLabelSelectors(ff.GetSourceLabel(), sourceLabels)
		if err != nil {
			return nil, fmt.Errorf("invalid source label filter: %v", err)
		}
		fs = append(fs, slf)
	}

	if ff.GetDestinationLabel() != nil {
		dlf, err := FilterByLabelSelectors(ff.GetDestinationLabel(), destinationLabels)
		if err != nil {
			return nil, fmt.Errorf("invalid destination label filter: %v", err)
		}
		fs = append(fs, dlf)
	}

	return fs, nil
}
