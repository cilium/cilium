// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package garp

import (
	"errors"
	"net/netip"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/mdlayher/arp"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type garpSuite struct{}

var _ = Suite(&garpSuite{})

func (s *garpSuite) TestGARPCell(c *C) {
	testutils.PrivilegedTest(c)

	testIfaceName := "lo"
	testGARPCell := func(garpSender Sender) error {
		s, _ := garpSender.(*sender)
		c.Assert(s, NotNil)
		c.Assert(s.iface.Name, Equals, testIfaceName)

		c.Logf("iface: %+v", s.iface)

		// Here we just want to make sure that the Send method works,
		// not that the gratuitous arp actually appears as expected. To
		// do this, we can try to Send on loopback, and just check to
		// see if we get the correct error from the underlying arp
		// package.
		err := garpSender.Send(netip.MustParseAddr("1.2.3.4"))
		if err != nil && errors.Is(err, arp.ErrInvalidHardwareAddr) {
			// We got the error we expected.
			return nil
		}

		c.Fatal(err)
		return nil
	}

	h := hive.New(cell.Module(
		"test-garp-cell",
		"TestGARPCell",
		Cell,
		cell.Invoke(testGARPCell),
	))
	hive.AddConfigOverride(h, func(cfg *Config) { cfg.GARPInterface = testIfaceName })

	if err := h.Populate(); err != nil {
		c.Fatalf("Failed to populate: %s", err)
	}
}
