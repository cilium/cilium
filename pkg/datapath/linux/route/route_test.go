// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"fmt"
	"net"
	"strings"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type RouteSuite struct{}

var _ = Suite(&RouteSuite{})

func parseIP(ip string) *net.IP {
	result := net.ParseIP(ip)
	return &result
}

func (p *RouteSuite) TestToIPCommand(c *C) {
	routes := []*Route{
		{
			Prefix: net.IPNet{
				IP:   net.ParseIP("10.0.0.1"),
				Mask: net.CIDRMask(8, 32),
			},
			Nexthop: parseIP("192.168.0.1"),
		},
		{
			Prefix: net.IPNet{
				IP:   net.ParseIP("::1"),
				Mask: net.CIDRMask(64, 128),
			},
			Nexthop: parseIP("ff02::2"),
		},
	}
	for _, r := range routes {
		dev := "eth0"
		v6 := "-6 "
		if r.Prefix.IP.To4() != nil {
			v6 = ""
		}
		masklen, _ := r.Prefix.Mask.Size()
		expRes := fmt.Sprintf("ip %sroute add %s/%d via %s dev %s", v6,
			r.Prefix.IP.String(), masklen, r.Nexthop.String(), dev)
		result := strings.Join(r.ToIPCommand(dev), " ")
		c.Assert(result, checker.DeepEquals, expRes)

		r.Nexthop = nil
		expRes = fmt.Sprintf("ip %sroute add %s/%d dev %s", v6,
			r.Prefix.IP.String(), masklen, dev)
		result = strings.Join(r.ToIPCommand(dev), " ")
		c.Assert(result, checker.DeepEquals, expRes)
	}
}
