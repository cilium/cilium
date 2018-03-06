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

package policy

import (
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestToBPFData(c *C) {
	cidrPolicy := NewCIDRPolicy()
	m := cidrPolicy.Ingress

	lbls := labels.LabelArray{}

	m.Insert("10.1.1.0/24", lbls)
	m.Insert("10.2.0.0/20", lbls)
	m.Insert("10.3.3.3/32", lbls)
	m.Insert("10.4.4.0/26", lbls)
	m.Insert("10.5.0.0/16", lbls)

	_, s4 := m.ToBPFData()
	exp := []int{32, 26, 24, 20, 16}
	for i := range s4 {
		c.Assert(s4[i], Equals, exp[i])
	}
}
