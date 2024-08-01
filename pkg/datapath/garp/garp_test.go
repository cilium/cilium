// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package garp

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/mdlayher/arp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestGARPCell(t *testing.T) {
	testutils.PrivilegedTest(t)

	testIfaceName := "lo"
	testGARPCell := func(garpSender Sender) error {
		s, _ := garpSender.(*sender)
		require.NotNil(t, s)
		require.Equal(t, testIfaceName, s.iface.Name)

		t.Logf("iface: %+v", s.iface)

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

		t.Fatal(err)
		return nil
	}

	h := hive.New(cell.Module(
		"test-garp-cell",
		"TestGARPCell",

		cell.Config(defaultConfig),
		cell.Provide(newGARPSender),
		cell.Invoke(testGARPCell),
	))
	hive.AddConfigOverride(h, func(cfg *Config) { cfg.L2PodAnnouncementsInterface = testIfaceName })

	if err := h.Populate(hivetest.Logger(t)); err != nil {
		t.Fatalf("Failed to populate: %s", err)
	}
}
