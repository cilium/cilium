// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"

	"k8s.io/apimachinery/pkg/util/intstr"
)

func (s *PolicyAPITestSuite) TestICMPFieldUnmarshal(c *C) {
	var i ICMPField

	value1 := []byte("{\"family\": \"IPv4\", \"type\": 8}")
	err := json.Unmarshal(value1, &i)

	icmpType := intstr.FromInt(8)
	c.Assert(i, checker.DeepEquals, ICMPField{Family: IPv4Family, Type: &icmpType})
	c.Assert(err, IsNil)

	// Check ICMPFIeld can treat ICMP type name
	value2 := []byte("{\"family\": \"IPv4\", \"type\": \"EchoRequest\"}")
	err = json.Unmarshal(value2, &i)

	icmpType = intstr.FromString("EchoRequest")
	c.Assert(i, checker.DeepEquals, ICMPField{Family: IPv4Family, Type: &icmpType})
	c.Assert(err, IsNil)

	// ICMP Node Information Query is only for IPv6
	value3 := []byte("{\"family\": \"IPv4\", \"type\": \"ICMPNodeInformationQuery\"}")
	err = json.Unmarshal(value3, &i)

	c.Assert(err, NotNil)
}
