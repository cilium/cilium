//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/cilium/cilium/pkg/lock/lockfile"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

const (
	BFDPort       = 3784
	BFDSourcePort = 49152
	BFDInterval   = 100_000
	BFDMultiplier = 3
)

var bfdDiscriminator atomic.Uint32

// LockBFDIntegrationTests serializes tests that use GoBGP's fixed BFD listener.
// The lock is process-wide so it also protects tests in different packages.
func LockBFDIntegrationTests(tb testing.TB) {
	tb.Helper()

	lockFile, err := lockfile.NewLockfile(filepath.Join(os.TempDir(), "cilium-bfd-integration.lock"))
	if err != nil {
		tb.Fatalf("failed to create BFD integration test lock: %v", err)
	}
	if err := lockFile.Lock(context.Background(), true); err != nil {
		_ = lockFile.Close()
		tb.Fatalf("failed to lock BFD integration tests: %v", err)
	}
	tb.Cleanup(func() {
		_ = lockFile.Unlock()
		_ = lockFile.Close()
	})
}

// BFDPeer is a minimal active BFD peer for integration tests. It exchanges
// real BFD control packets with GoBGP while keeping BGP itself out of the
// test.
type BFDPeer struct {
	listener      net.PacketConn
	sender        net.PacketConn
	discriminator uint32
	responding    atomic.Bool
	packets       atomic.Uint64
	up            atomic.Bool
	lastMu        sync.RWMutex
	last          *bfd.BFDHeader
	stopOnce      sync.Once
	done          chan struct{}
}

// NewBFDPeer starts a BFD peer on address and registers its cleanup with tb.
func NewBFDPeer(tb testing.TB, address string) *BFDPeer {
	tb.Helper()

	listenerConfig := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	listener, err := listenerConfig.ListenPacket(context.Background(), "udp4", net.JoinHostPort(address, strconv.Itoa(BFDPort)))
	if err != nil {
		tb.Fatalf("failed to listen for BFD packets: %v", err)
	}

	senderConfig := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 255)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	sender, err := senderConfig.ListenPacket(context.Background(), "udp4", net.JoinHostPort(address, strconv.Itoa(BFDSourcePort)))
	if err != nil {
		_ = listener.Close()
		tb.Fatalf("failed to create BFD sender: %v", err)
	}

	peer := &BFDPeer{
		listener:      listener,
		sender:        sender,
		discriminator: bfdDiscriminator.Add(1),
		done:          make(chan struct{}),
	}
	peer.responding.Store(true)
	go peer.run()
	tb.Cleanup(peer.Stop)
	return peer
}

func (p *BFDPeer) SetResponding(responding bool) {
	p.responding.Store(responding)
}

func (p *BFDPeer) SawUp() bool {
	return p.up.Load()
}

func (p *BFDPeer) PacketCount() uint64 {
	return p.packets.Load()
}

func (p *BFDPeer) LastPacket() (*bfd.BFDHeader, bool) {
	p.lastMu.RLock()
	defer p.lastMu.RUnlock()
	if p.last == nil {
		return nil, false
	}
	packet := *p.last
	return &packet, true
}

func (p *BFDPeer) Stop() {
	p.stopOnce.Do(func() {
		_ = p.listener.Close()
		_ = p.sender.Close()
		<-p.done
	})
}

func (p *BFDPeer) run() {
	defer close(p.done)

	buffer := make([]byte, 4096)
	for {
		length, remote, err := p.listener.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		request := &bfd.BFDHeader{}
		if err := request.UnmarshalBinary(buffer[:length]); err != nil {
			continue
		}
		p.packets.Add(1)
		p.lastMu.Lock()
		p.last = request
		p.lastMu.Unlock()
		if request.State == bfd.StateUp {
			p.up.Store(true)
		}
		if !p.responding.Load() {
			continue
		}

		state := bfd.StateDown
		switch request.State {
		case bfd.StateInit:
			state = bfd.StateInit
		case bfd.StateUp:
			state = bfd.StateUp
		}
		response := &bfd.BFDHeader{
			Version:               1,
			State:                 state,
			DetectTimeMultiplier:  BFDMultiplier,
			MyDiscriminator:       p.discriminator,
			YourDiscriminator:     request.MyDiscriminator,
			DesiredMinTxInterval:  BFDInterval,
			RequiredMinRxInterval: BFDInterval,
		}
		payload, err := response.MarshalBinary()
		if err != nil {
			continue
		}

		remoteUDP, ok := remote.(*net.UDPAddr)
		if !ok {
			continue
		}
		_, _ = p.sender.WriteTo(payload, &net.UDPAddr{IP: remoteUDP.IP, Port: BFDPort})
	}
}
