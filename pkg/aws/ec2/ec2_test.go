// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package ec2

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type Filters []ec2_types.Filter

func (s Filters) Len() int           { return len(s) }
func (s Filters) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Filters) Less(i, j int) bool { return strings.Compare(*s[i].Name, *s[j].Name) > 0 }

func TestNewSubnetsFilters(t *testing.T) {
	type args struct {
		tags map[string]string
		ids  []string
	}
	tests := []struct {
		name string
		args args
		want []ec2_types.Filter
	}{

		{
			name: "empty arguments",
			args: args{
				tags: map[string]string{},
				ids:  []string{},
			},
			want: []ec2_types.Filter{},
		},

		{
			name: "ids only",
			args: args{
				tags: map[string]string{},
				ids:  []string{"a", "b"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("subnet-id"),
					Values: []string{"a", "b"},
				},
			},
		},

		{
			name: "tags only",
			args: args{
				tags: map[string]string{"a": "b", "c": "d"},
				ids:  []string{},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("tag:c"),
					Values: []string{"d"},
				},
			},
		},

		{
			name: "tags and ids",
			args: args{
				tags: map[string]string{"a": "b"},
				ids:  []string{"c", "d"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("subnet-id"),
					Values: []string{"c", "d"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSubnetsFilters(tt.args.tags, tt.args.ids)
			sort.Sort(Filters(got))
			sort.Sort(Filters(tt.want))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSubnetsFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}
