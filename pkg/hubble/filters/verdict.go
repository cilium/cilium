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

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByVerdicts(vs []flowpb.Verdict) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		for _, verdict := range vs {
			if verdict == flow.GetVerdict() {
				return true
			}
		}

		return false
	}
}

// VerdictFilter implements filtering based on forwarding verdict
type VerdictFilter struct{}

// OnBuildFilter builds a forwarding verdict filter
func (v *VerdictFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetVerdict() != nil {
		fs = append(fs, filterByVerdicts(ff.GetVerdict()))
	}

	return fs, nil
}
