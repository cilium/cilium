//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

const (
	BFDPort       = 3784
	BFDSourcePort = 49152
	BFDInterval   = 100_000
	BFDMultiplier = 3
)

// BFDPeer is a stub for platforms where the BFD integration tests are not run.
type BFDPeer struct{}

// LockBFDIntegrationTests is a no-op on unsupported platforms.
func LockBFDIntegrationTests(testing.TB) {}

// NewBFDPeer skips callers that try to use the Linux-only BFD test peer.
func NewBFDPeer(tb testing.TB, _ string) *BFDPeer {
	tb.Helper()
	tb.Skip("BFD integration tests require Linux loopback addressing and socket options")
	return nil
}

func (*BFDPeer) SetResponding(bool) {}

func (*BFDPeer) SawUp() bool { return false }

func (*BFDPeer) PacketCount() uint64 { return 0 }

func (*BFDPeer) LastPacket() (*bfd.BFDHeader, bool) { return nil, false }

func (*BFDPeer) Stop() {}
