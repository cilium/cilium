// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func mustTCProgram(t *testing.T) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		t.Skipf("tc programs not supported: %s", err)
	}
	t.Cleanup(func() {
		p.Close()
	})
	return p
}

func mustXDPProgram(t *testing.T) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		t.Skipf("xdp programs not supported: %s", err)
	}
	t.Cleanup(func() {
		p.Close()
	})
	return p
}

func TestAttachRemoveTCProgram(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		ifName := "dummy0"
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
		}
		err := netlink.LinkAdd(dummy)
		require.NoError(t, err)

		prog := mustTCProgram(t)

		err = attachTCProgram(dummy, prog, "test", directionToParent(dirEgress))
		require.NoError(t, err)

		filters, err := netlink.FilterList(dummy, directionToParent(dirEgress))
		require.NoError(t, err)
		require.NotEmpty(t, filters)

		err = removeTCFilters(dummy.Attrs().Name, directionToParent(dirEgress))
		require.NoError(t, err)

		filters, err = netlink.FilterList(dummy, directionToParent(dirEgress))
		require.NoError(t, err)
		require.Empty(t, filters)

		err = netlink.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}

func TestSetupIPIPDevices(t *testing.T) {
	testutils.PrivilegedTest(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		err := setupIPIPDevices(sysctl, true, true)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)

		_, err = netlink.LinkByName("cilium_tunl")
		require.NoError(t, err)

		_, err = netlink.LinkByName("cilium_ip6tnl")
		require.NoError(t, err)

		_, err = netlink.LinkByName("tunl0")
		require.Error(t, err)

		_, err = netlink.LinkByName("ip6tnl0")
		require.Error(t, err)

		err = setupIPIPDevices(sysctl, false, false)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		return nil
	})
}
