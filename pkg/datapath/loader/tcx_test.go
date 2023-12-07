// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestAttachDetachTCX(t *testing.T) {
	testutils.PrivilegedTest(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustTCProgramWithName(t, "cil_test")
		linkDir := testutils.TempBPFFS(t)

		// Attaching the same program twice should result in a link create and update.
		require.NoError(t, attachTCProgram(lo, prog, "cil_test", linkDir, directionToParent(dirEgress)))
		require.NoError(t, attachTCProgram(lo, prog, "cil_test", linkDir, directionToParent(dirEgress)))

		// Query tcx programs.
		hasPrograms, err := hasCiliumTCXLinks(lo, ebpf.AttachTCXEgress)
		require.NoError(t, err)
		require.True(t, hasPrograms)

		// Detach the program.
		err = detachTCProgram(lo, "cil_test", linkDir, directionToParent(dirEgress))
		require.NoError(t, err)

		// bpf_prog_query is eventually-consistent, retries may be necessary.
		require.NoError(t, testutils.WaitUntil(func() bool {
			hasPrograms, err := hasCiliumTCXLinks(lo, ebpf.AttachTCXIngress)
			require.NoError(t, err)
			return !hasPrograms
		}, time.Second))

		return nil
	})
}

func TestHasCiliumTCXLinks(t *testing.T) {
	testutils.PrivilegedTest(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		// No tcx progs attached, expect false.
		hasPrograms, err := hasCiliumTCXLinks(lo, ebpf.AttachTCXEgress)
		require.NoError(t, err)
		require.False(t, hasPrograms)

		l1, err := link.AttachTCX(link.TCXOptions{
			Program:   mustTCProgram(t),
			Attach:    ebpf.AttachTCXEgress,
			Interface: lo.Attrs().Index,
			Anchor:    link.Tail(),
		})
		require.NoError(t, err)

		// tcx program without cil_ prefix is attached, expect false.
		hasPrograms, err = hasCiliumTCXLinks(lo, ebpf.AttachTCXEgress)
		require.NoError(t, err)
		require.False(t, hasPrograms)

		l2, err := link.AttachTCX(link.TCXOptions{
			Program:   mustTCProgramWithName(t, "cil_test"),
			Attach:    ebpf.AttachTCXEgress,
			Interface: lo.Attrs().Index,
			Anchor:    link.Tail(),
		})
		require.NoError(t, err)

		// tcx program with cil_ prefix is attached, expect true.
		hasPrograms, err = hasCiliumTCXLinks(lo, ebpf.AttachTCXEgress)
		require.NoError(t, err)
		require.True(t, hasPrograms)

		require.NoError(t, l1.Close())
		require.NoError(t, l2.Close())

		return nil
	})
}

func skipTCXUnsupported(tb testing.TB) {
	tb.Helper()

	err := onceTCX()
	if errors.Is(err, ebpf.ErrNotSupported) {
		tb.Skip("tcx is not supported")
	}
	if err != nil {
		tb.Fatalf("probing tcx support: %s", err)
	}
}

var onceTCX = sync.OnceValue(func() error {
	prog, err := newTCProgram()
	if err != nil {
		return err
	}
	defer prog.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
		Interface: lo.Attrs().Index,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return fmt.Errorf("creating link: %w", err)
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("closing link: %w", err)
	}

	return nil
})
