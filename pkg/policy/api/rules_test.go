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

package api

import (
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/labels"
)

func TestRules_GetSetOfLabels(t *testing.T) {
	tests := []struct {
		name string
		rs   Rules
		want []labels.LabelArray
	}{
		{
			name: "duplicated foo=bar",
			rs: Rules{
				{
					Labels: labels.ParseLabelArrayFromArray([]string{"foo=bar"}),
				},
				{
					Labels: labels.ParseLabelArrayFromArray([]string{"foo=bar"}),
				},
				{
					Labels: labels.ParseLabelArrayFromArray([]string{"foo=baz"}),
				},
			},
			want: []labels.LabelArray{
				labels.ParseLabelArrayFromArray([]string{"foo=bar"}),
				labels.ParseLabelArrayFromArray([]string{"foo=baz"}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rs.GetSetOfLabels(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Rules.GetSetOfLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}
