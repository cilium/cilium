// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/types"
)

// bmpCommonHeaderLen is the length of the BMP per-message Common Header
// (RFC 7854 section 4.1): 1 byte version + 4 bytes length + 1 byte type.
const bmpCommonHeaderLen = 6

// bmpMsgTypeInitiation is the BMP Initiation message type (RFC 7854 section 4.3).
const bmpMsgTypeInitiation = 4

// fakeBMPStation is a minimal TCP listener that accepts a single BMP client
// connection and reports the first message's common-header fields.
type fakeBMPStation struct {
	ln       net.Listener
	firstMsg chan bmpHeader
	errCh    chan error
}

type bmpHeader struct {
	version uint8
	length  uint32
	msgType uint8
}

func newFakeBMPStation(t *testing.T) *fakeBMPStation {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &fakeBMPStation{
		ln:       ln,
		firstMsg: make(chan bmpHeader, 1),
		errCh:    make(chan error, 1),
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			s.errCh <- err
			return
		}
		defer conn.Close()

		hdr := make([]byte, bmpCommonHeaderLen)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			s.errCh <- err
			return
		}
		s.firstMsg <- bmpHeader{
			version: hdr[0],
			length:  binary.BigEndian.Uint32(hdr[1:5]),
			msgType: hdr[5],
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeBMPStation) addr(t *testing.T) (string, uint32) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, uint32(port)
}

// TestAddBMP verifies that AddBMP causes the embedded GoBGP server to open a BMP
// session to the configured station and send a valid BMP Initiation message.
func TestAddBMP(t *testing.T) {
	router, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), testServerParameters)
	require.NoError(t, err)
	t.Cleanup(func() {
		router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
	})

	station := newFakeBMPStation(t)
	host, port := station.addr(t)

	bmp := &types.BMPServer{
		Address:          host,
		Port:             port,
		MonitoringPolicy: types.BMPMonitoringPolicyPre,
		SysName:          "cilium-test-node",
		SysDescr:         "cilium bmp prototype",
	}

	err = router.AddBMP(context.Background(), bmp)
	require.NoError(t, err)

	select {
	case hdr := <-station.firstMsg:
		// RFC 7854: BMP version is 3, first message from a monitored router is
		// an Initiation message.
		require.Equal(t, uint8(3), hdr.version, "unexpected BMP version")
		require.Equal(t, uint8(bmpMsgTypeInitiation), hdr.msgType, "expected BMP Initiation message first")
		require.GreaterOrEqual(t, hdr.length, uint32(bmpCommonHeaderLen), "BMP message length too small")
	case err := <-station.errCh:
		t.Fatalf("fake BMP station error: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for BMP connection from GoBGP")
	}

	// RemoveBMP must tear the station down without error.
	err = router.RemoveBMP(context.Background(), bmp)
	require.NoError(t, err)
}
