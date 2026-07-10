// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedRemoveStaleEPIfaces(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "lxc12345"
		veth := &netlink.Veth{
			LinkAttrs: linkAttrs,
			PeerName:  "tmp54321",
		}

		err := netlink.LinkAdd(veth)
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.NoError(t, err)

		restorer := &endpointRestorer{logger: hivetest.Logger(t)}
		err = restorer.clearStaleCiliumEndpointVeths()
		assert.NoError(t, err)

		// Check that stale iface is removed
		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}
