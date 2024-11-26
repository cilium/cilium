// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func newTCProgram() (*ebpf.Program, error) {
	return ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
}

func mustTCProgram(tb testing.TB) *ebpf.Program {
	p, err := newTCProgram()
	if err != nil {
		tb.Skipf("tc programs not supported: %s", err)
	}
	tb.Cleanup(func() {
		p.Close()
	})
	return p
}

func mustTCProgramWithName(t *testing.T, name string) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: name,
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

func TestAttachDetachSKBProgramLegacy(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustTCProgram(t)
		linkDir := testutils.TempBPFFS(t)

		require.NoError(t, attachSKBProgram(lo, prog, "cil_test", linkDir, directionToParent(dirEgress), false))
		hasFilters, err := hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.True(t, hasFilters)

		require.NoError(t, detachSKBProgram(lo, "cil_test", linkDir, directionToParent(dirEgress)))
		hasFilters, err = hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.False(t, hasFilters)

		return nil
	})
}

func TestAttachDetachTCProgram(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustTCProgram(t)

		require.NoError(t, upsertTCProgram(lo, prog, "cil_test", directionToParent(dirEgress), 1))
		hasFilters, err := hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.True(t, hasFilters)

		require.NoError(t, removeTCFilters(lo, directionToParent(dirEgress)))
		hasFilters, err = hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.False(t, hasFilters)

		return nil
	})
}

func TestHasCiliumTCFilters(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		// Test if function succeeds and returns false if no filters are attached
		hasFilters, err := hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.False(t, hasFilters)

		prog := mustTCProgram(t)

		err = upsertTCProgram(lo, prog, "no_prefix_test", directionToParent(dirEgress), 1)
		require.NoError(t, err)

		// Test if function succeeds and return false if no filter with 'cil' prefix is attached
		hasFilters, err = hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.False(t, hasFilters)

		err = upsertTCProgram(lo, prog, "cil_test", directionToParent(dirEgress), 1)
		require.NoError(t, err)

		// Test if function succeeds and return true if filter with 'cil' prefix is attached
		hasFilters, err = hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.True(t, hasFilters)

		return nil
	})
}

// Upgrade a legacy tc program to tcx.
func TestAttachSKBUpgrade(t *testing.T) {
	testutils.PrivilegedTest(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustTCProgramWithName(t, "cil_test")
		linkDir := testutils.TempBPFFS(t)

		// Use the cil_ prefix so the attachment algorithm knows which tc filter to
		// clean up after attaching tcx.
		require.NoError(t, upsertTCProgram(lo, prog, "cil_test", directionToParent(dirEgress), 1))

		require.NoError(t, attachSKBProgram(lo, prog, "cil_test", linkDir, directionToParent(dirEgress), true))

		hasFilters, err := hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.False(t, hasFilters)

		require.NoError(t, testutils.WaitUntil(func() bool {
			hasLinks, err := hasCiliumTCXLinks(lo, ebpf.AttachTCXEgress)
			require.NoError(t, err)
			return hasLinks
		}, time.Second))

		return nil
	})
}

// Downgrade a tcx program to legacy tc.
func TestAttachSKBDowngrade(t *testing.T) {
	testutils.PrivilegedTest(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustTCProgramWithName(t, "cil_test")
		linkDir := testutils.TempBPFFS(t)

		require.NoError(t, upsertTCXProgram(lo, prog, "cil_test", linkDir, directionToParent(dirEgress)))

		require.NoError(t, attachSKBProgram(lo, prog, "cil_test", linkDir, directionToParent(dirEgress), false))

		hasFilters, err := hasCiliumTCFilters(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.True(t, hasFilters)

		require.NoError(t, testutils.WaitUntil(func() bool {
			hasLinks, err := hasCiliumTCXLinks(lo, ebpf.AttachTCXEgress)
			require.NoError(t, err)
			return !hasLinks
		}, time.Second))

		return nil
	})
}

func TestCleanupStaleTCFilters(t *testing.T) {
	testutils.PrivilegedTest(t)

	netns.NewNetNS(t).Do(func() error {
		prog := mustTCProgram(t)

		// Attach 2 filters with a name that doesn't match the prefix, so they're
		// not implicitly cleaned up.
		require.NoError(t, upsertTCProgram(lo, prog, "cil_test_1", directionToParent(dirEgress), 1))
		require.NoError(t, upsertTCProgram(lo, prog, "cil_test_2", directionToParent(dirEgress), 2))

		filters, err := safenetlink.FilterList(lo, directionToParent(dirEgress))
		require.NoError(t, err)
		require.Len(t, filters, 1)

		require.EqualValues(t, 2, filters[0].Attrs().Priority)

		return nil
	})
}
