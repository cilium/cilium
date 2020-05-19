// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"context"
	"fmt"
	"regexp"

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

	translated := labelSelectorWithColon.ReplaceAllString(selector, "${1}.${2}")
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
