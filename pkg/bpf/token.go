// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

const (
	// BPF_TOKEN_CREATE is the BPF syscall command to create a token
	BPF_TOKEN_CREATE = 36
	// BPF_F_TOKEN_FD is the flag to indicate a token FD is provided
	BPF_F_TOKEN_FD = 1 << 16
)

// tokenPaths are the paths to check for BPF tokens, in order of preference
var tokenPaths = []string{
	"/run/bpf_delegation", // Common delegation path
	"/sys/fs/bpf",         // Default BPFFS mount
}

// globalTokenFD stores the global BPF token for use by probes and other early code
var globalTokenFD int = -1
var globalTokenMu sync.Mutex
var globalTokenInitialized bool

// init tries to initialize the BPF token as early as possible.
// This runs during package initialization, before main() starts.
// If the token cannot be obtained, we continue in privileged mode.
func init() {
	fd, err := OpenBPFToken("")
	if err != nil || fd <= 0 {
		// Token not available - continue in privileged mode
		globalTokenFD = -1
	} else {
		globalTokenFD = fd
		// Also set it in the ebpf library's internal storage so that
		// library-level feature probes can use it
		features.SetGlobalToken(fd)
	}
	globalTokenInitialized = true
}

// GetGlobalToken returns the global BPF token FD.
// Returns -1 if no token is available. The token is initialized once at startup.
func GetGlobalToken() int {
	return globalTokenFD
}

// OpenBPFToken opens a BPF token from the configured or discovered path.
// Returns -1 if tokens are not available (graceful fallback).
// Returns the token file descriptor if successful.
func OpenBPFToken(configuredPath string) (int, error) {
	// 1. Check explicit configuration
	if configuredPath != "" {
		return openTokenPath(configuredPath)
	}

	// 2. Check environment variable (libbpf convention)
	if envPath := os.Getenv("LIBBPF_BPF_TOKEN_PATH"); envPath != "" {
		return openTokenPath(envPath)
	}

	// 3. Try common paths
	for _, path := range tokenPaths {
		if fd, err := openTokenPath(path); err == nil {
			return fd, nil
		}
	}

	// Tokens not available - return -1 for graceful fallback
	return -1, nil
}

// openTokenPath attempts to create a BPF token from the given BPFFS path
func openTokenPath(path string) (int, error) {
	// Open BPFFS mount point
	bpffsFd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(bpffsFd)

	// Create BPF token via syscall
	attr := struct {
		Flags   uint32
		BpffsFd uint32
	}{
		Flags:   0,
		BpffsFd: uint32(bpffsFd),
	}

	tokenFd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_TOKEN_CREATE,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		if errno == unix.EINVAL {
			// EINVAL typically means the kernel doesn't support tokens or
			// the BPFFS doesn't have delegation enabled
			return -1, errors.New("BPF tokens not supported by kernel or BPFFS not configured for delegation")
		}
		return -1, errno
	}

	// Set O_CLOEXEC on the token FD
	if _, err := unix.FcntlInt(uintptr(tokenFd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		unix.Close(int(tokenFd))
		return -1, err
	}

	return int(tokenFd), nil
}
