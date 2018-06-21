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

package identity

import (
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *IdentityTestSuite) TestLookupReservedIdentity(c *C) {
	hostID := GetReservedID("host")
	c.Assert(LookupIdentityByID(hostID), Not(IsNil))

	identity := LookupIdentity(labels.NewLabelsFromModel([]string{"reserved:host"}))
	c.Assert(identity, Not(IsNil))
	c.Assert(identity.ID, Equals, hostID)

	worldID := GetReservedID("world")
	c.Assert(LookupIdentityByID(worldID), Not(IsNil))

	identity = LookupIdentity(labels.NewLabelsFromModel([]string{"reserved:world"}))
	c.Assert(identity, Not(IsNil))
	c.Assert(identity.ID, Equals, worldID)
}

func (s *IdentityTestSuite) TestLookupReservedIdentityByLabels(c *C) {
	ni, err := ParseNumericIdentity("129")
	c.Assert(err, IsNil)
	AddUserDefinedNumericIdentity(ni, "kvstore")
	AddReservedIdentity(ni, "kvstore")

	type args struct {
		lbls labels.Labels
	}
	tests := []struct {
		name string
		args args
		want *Identity
	}{
		{
			name: "fixed-identity",
			args: args{
				lbls: labels.Labels{labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kvstore")},
			},
			want: NewIdentity(ni, labels.Labels{"kvstore": labels.NewLabel("kvstore", "", labels.LabelSourceReserved)}),
		},
		{
			name: "non-existing-fixed-identity",
			args: args{
				lbls: labels.Labels{labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kube-dns")},
			},
			want: nil,
		},
		{
			name: "reserved-identity",
			args: args{
				lbls: labels.Labels{labels.LabelSourceReserved: labels.NewLabel(labels.LabelSourceReservedKeyPrefix+"host", "", labels.LabelSourceReserved)},
			},
			want: NewIdentity(ReservedIdentityHost, labels.Labels{"host": labels.ParseLabel("reserved:host")}),
		},
		{
			name: "reserved-identity+other-labels",
			args: args{
				lbls: labels.Labels{
					labels.LabelSourceReserved: labels.ParseLabel("reserved:host"),
					"id.foo":                   labels.ParseLabel("id.foo"),
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		got := LookupReservedIdentityByLabels(tt.args.lbls)
		switch {
		case got == nil && tt.want == nil:
		case got == nil && tt.want != nil ||
			got != nil && tt.want == nil ||
			got.ID != tt.want.ID:

			c.Errorf("test %s: LookupReservedIdentityByLabels() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
