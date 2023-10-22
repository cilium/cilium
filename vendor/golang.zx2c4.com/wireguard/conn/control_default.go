//go:build !linux || android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net/netip"

func (e *StdNetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e *StdNetEndpoint) SrcIfidx() int32 {
	return 0
}

func (e *StdNetEndpoint) SrcToString() string {
	return ""
}

// TODO: macOS, FreeBSD and other BSDs likely do support the sticky sockets
// {get,set}srcControl feature set, but use alternatively named flags and need
// ports and require testing.

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint) {
}

// setSrcControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func setSrcControl(control *[]byte, ep *StdNetEndpoint) {
}

// getGSOSize parses control for UDP_GRO and if found returns its GSO size data.
func getGSOSize(control []byte) (int, error) {
	return 0, nil
}

// setGSOSize sets a UDP_SEGMENT in control based on gsoSize.
func setGSOSize(control *[]byte, gsoSize uint16) {
}

// controlSize returns the recommended buffer size for pooling sticky and UDP
// offloading control data.
const controlSize = 0

const StdNetSupportsStickySockets = false
