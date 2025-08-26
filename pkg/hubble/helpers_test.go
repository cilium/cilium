// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"fmt"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/testutils"

	"github.com/stretchr/testify/assert"
)

func TestParseFlowFilters(t *testing.T) {
	testCases := []struct {
		name    string
		arg     string
		want    []*flowpb.FlowFilter
		wantErr bool
	}{
		// valid
		{name: "empty"},
		{name: "whitespaces", arg: "   "},
		{name: "one json", arg: "{}", want: []*flowpb.FlowFilter{{}}},
		{name: "one json whitespaces", arg: "{}  ", want: []*flowpb.FlowFilter{{}}},
		{
			name: "one json whitespaces",
			arg:  ` { "source_ip": ["1.2.3.4",  "2.3.4.5"]  } `,
			want: []*flowpb.FlowFilter{{
				SourceIp: []string{"1.2.3.4", "2.3.4.5"},
			}},
		},
		{name: "two jsons", arg: "{}{}", want: []*flowpb.FlowFilter{{}, {}}},
		{name: "two jsons whitespaces", arg: "{}  {}", want: []*flowpb.FlowFilter{{}, {}}},
		{name: "two jsons whitespaces", arg: "{}  {}   ", want: []*flowpb.FlowFilter{{}, {}}},
		{
			name: "two json whitespaces",
			arg: `
                { "source_ip": ["1.2.3.4",  "2.3.4.5"],
                  "destination_ip": ["2.3.4.5", "1.2.3.4"] }
                { "destination_pod": ["mypod1",  "mypod2"]  }
            `,
			want: []*flowpb.FlowFilter{
				{SourceIp: []string{"1.2.3.4", "2.3.4.5"}, DestinationIp: []string{"2.3.4.5", "1.2.3.4"}},
				{DestinationPod: []string{"mypod1", "mypod2"}},
			},
		},
		// invalid
		{name: "quoted json", arg: "'{}'", wantErr: true},
		{name: "quoted jsons", arg: "'{}''{}'", wantErr: true},
		{name: "comma delimited", arg: "{},{}", wantErr: true},
		{name: "json array", arg: "[]", wantErr: true},
		{name: "json array", arg: "[{}]", wantErr: true},
		{name: "json array", arg: "[{},{}]", wantErr: true},
		{name: "invalid json", arg: "{", wantErr: true},
		{name: "invalid json", arg: "{}}", wantErr: true},
		{name: "invalid json", arg: "}}", wantErr: true},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d-%s", i, tc.name), func(t *testing.T) {
			got, err := ParseFlowFilters(tc.arg)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			testutils.AssertProtoEqual(t, tc.want, got)
		})
	}
}
