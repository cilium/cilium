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

func (s *IdentityTestSuite) TestAllocateIdentity(c *C) {
	err := AddUserDefinedNumericIdentitySet(map[string]string{"129": "kube-dns"})
	c.Assert(err, IsNil)
	defer DelReservedNumericIdentity(NumericIdentity(129))

	type args struct {
		lbls labels.Labels
	}
	type want struct {
		id    *Identity
		isNew bool
		err   error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "getting only the reserved identity label should return the numeric identity of the fixed label",
			args: args{
				lbls: labels.NewLabelsFromSortedList("reserved:" + labels.LabelKeyFixedIdentity + "=kube-dns"),
			},
			want: want{
				id: NewIdentity(
					NumericIdentity(129),
					labels.NewLabelsFromSortedList("reserved:"+labels.LabelKeyFixedIdentity+"=kube-dns"),
				),
				isNew: false,
				err:   nil,
			},
		},
		{
			name: "getting the reserved identity label plus a user label should return the numeric identity of the fixed label",
			args: args{
				labels.NewLabelsFromSortedList(
					"id.foo=bar;" +
						"reserved:" + labels.LabelKeyFixedIdentity + "=kube-dns",
				),
			},
			want: want{
				id: NewIdentity(
					NumericIdentity(129),
					labels.NewLabelsFromSortedList(
						"id.foo=bar;"+
							"reserved:"+labels.LabelKeyFixedIdentity+"=kube-dns",
					),
				),
				isNew: false,
				err:   nil,
			},
		},
	}
	for _, tt := range tests {
		id, isNew, err := AllocateIdentity(tt.args.lbls)
		c.Assert(err, Equals, tt.want.err, Commentf("Test Name: %s", tt.name))
		c.Assert(isNew, Equals, tt.want.isNew, Commentf("Test Name: %s", tt.name))
		c.Assert(id, DeepEquals, tt.want.id, Commentf("Test Name: %s", tt.name))
	}
}
