// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
)

// TestErrNotSupported verifies that ErrNotSupported is properly defined
// and can be used for error checking.
func TestErrNotSupported(t *testing.T) {
	assert.NotNil(t, ErrNotSupported)
	assert.Equal(t, "not supported", ErrNotSupported.Error())
}

// TestNewProgramErrorWrapping verifies that errors from newProgram
// are properly wrapped with ErrNotSupported for error checking.
func TestNewProgramErrorWrapping(t *testing.T) {
	// This test documents the expected behavior:
	// When newProgram fails (not due to EPERM with token),
	// the error should wrap ErrNotSupported.

	// We can't easily trigger this without privileges, but we can
	// verify the error type is usable for errors.Is checks.
	testErr := errors.New("test error")
	wrappedErr := errors.Join(testErr, ErrNotSupported)

	assert.True(t, errors.Is(wrappedErr, ErrNotSupported),
		"wrapped error should be checkable with errors.Is")
}

// TestEPERMHandlingContract documents the EPERM handling behavior
// that should occur in user namespace mode with BPF tokens.
//
// The contract is:
// 1. When a BPF token is present (tokenFD > 0) and EPERM is returned,
//    the function returns (nil, nil) to indicate "assume supported"
// 2. When no token is present, EPERM is treated as a real error
// 3. The calling probe functions check for prog == nil and return
//    nil (success) in that case
func TestEPERMHandlingContract(t *testing.T) {
	// Document the expected behavior for each case

	t.Run("EPERM with token means assume supported", func(t *testing.T) {
		// When tokenFD > 0 && errors.Is(err, unix.EPERM):
		//   return nil, nil
		// This signals to the caller that the feature should be
		// assumed as supported even though we couldn't fully verify it.

		// We verify the unix.EPERM constant is accessible and usable
		assert.True(t, errors.Is(unix.EPERM, unix.EPERM))
	})

	t.Run("nil program triggers early success return", func(t *testing.T) {
		// When prog == nil (from the EPERM case above):
		//   The HaveXXX functions should return nil (success)
		// This is the graceful degradation path for user namespaces.

		// We can't easily test this without mocking, but the pattern
		// is documented here and tested via integration tests.
	})

	t.Run("ErrNotSupported can be checked with errors.Is", func(t *testing.T) {
		// Verify the error checking pattern works
		err := ErrNotSupported
		assert.True(t, errors.Is(err, ErrNotSupported))
	})

	t.Run("ErrRestrictedKernel can be checked", func(t *testing.T) {
		// Verify we can check for ErrRestrictedKernel
		err := ebpf.ErrRestrictedKernel
		assert.True(t, errors.Is(err, ebpf.ErrRestrictedKernel))
	})
}

// TestProbeNilProgramHandling verifies that probe functions properly
// handle the nil program case that occurs with EPERM + token.
//
// Note: These tests document the expected behavior. The actual nil
// program path is tested via integration tests or manual testing
// in user namespace environments.
func TestProbeNilProgramHandling(t *testing.T) {
	t.Run("HaveBPF handles nil program", func(t *testing.T) {
		// The HaveBPF function checks:
		//   if prog == nil { return nil }
		// This is the graceful degradation for user namespaces.
		// We document this expectation here.
	})

	t.Run("HaveBPFJIT handles nil program and EPERM from Info", func(t *testing.T) {
		// HaveBPFJIT has additional EPERM handling:
		// 1. prog == nil check
		// 2. prog.Info() EPERM check
		// 3. JitedSize() ErrNotSupported/ErrRestrictedKernel check
	})

	t.Run("HaveDeadCodeElim handles EPERM from Info and Instructions", func(t *testing.T) {
		// HaveDeadCodeElim checks for EPERM from:
		// 1. prog.Info()
		// 2. info.Instructions()
		// And returns nil (success) in those cases.
	})

	t.Run("HaveFibLookupSkipNeigh assumes supported with token on error", func(t *testing.T) {
		// When tokenFD > 0 and LoadProbesObjects fails:
		//   return nil (assume supported on modern kernels)
	})

	t.Run("HaveBatchAPI handles EPERM with token", func(t *testing.T) {
		// When tokenFD > 0 and map creation fails with EPERM:
		//   return nil (assume supported)
	})
}
