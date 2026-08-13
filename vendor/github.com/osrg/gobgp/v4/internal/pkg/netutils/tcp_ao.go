// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutils

import (
	"errors"
	"net/netip"
)

// tcpAOMaxKeyLen defines maximum TCP-AO key length, matching Linux TCP_AO_MAXKEYLEN:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L369
const tcpAOMaxKeyLen = 80

// ErrTCPAONotSupported is returned when TCP-AO is requested on a platform for which GoBGP does not provide support.
var ErrTCPAONotSupported = errors.New("TCP-AO is not supported on this platform")

// TCPAOAlgorithm identifies an RFC 5926 TCP-AO algorithm profile.
type TCPAOAlgorithm uint8

const (
	TCPAOAlgorithmUnspecified TCPAOAlgorithm = iota
	TCPAOAlgorithmHMACSHA1
	TCPAOAlgorithmAES128CMAC
)

// TCPAOKey contains socket-level properties of one TCP-AO key.
type TCPAOKey struct {
	SendID            uint8
	ReceiveID         uint8
	Algorithm         TCPAOAlgorithm
	MasterKey         []byte
	ExcludeTCPOptions bool
}

// TCPAOConfig contains all keys used by a TCP-AO socket operation.
// PreferredSendID optionally selects a key from Keys.
type TCPAOConfig struct {
	Keys            []TCPAOKey
	PreferredSendID *uint8
}

// TCPAOKeyState contains the operational state for one TCP-AO key installed on a socket.
type TCPAOKeyState struct {
	Peer           netip.Prefix
	InterfaceIndex int32
	SendID         uint8
	ReceiveID      uint8
	Current        bool
	ReceiveNext    bool
	PacketsGood    uint64
	PacketsBad     uint64
}

// TCPAOSocketCounters contains operational counters maintained for a TCP-AO socket.
type TCPAOSocketCounters struct {
	PacketsKeyNotFound uint64
	PacketsAORequired  uint64
	PacketsDroppedICMP uint64
}
