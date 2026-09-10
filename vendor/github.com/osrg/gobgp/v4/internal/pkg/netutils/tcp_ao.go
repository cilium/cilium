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
	"fmt"
	"net/netip"
)

// TCPAOMaxKeyLen defines maximum TCP-AO key length, matching Linux TCP_AO_MAXKEYLEN:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L369
const TCPAOMaxKeyLen = 80

// ErrTCPAONotSupported is returned when TCP-AO is requested on a platform for which GoBGP does not provide support.
var ErrTCPAONotSupported = errors.New("TCP-AO is not supported on this platform")

// TCPAOAlgorithm identifies a TCP-AO algorithm profile.
type TCPAOAlgorithm uint8

const (
	TCPAOAlgorithmUnspecified TCPAOAlgorithm = iota
	TCPAOAlgorithmHMACSHA1
	TCPAOAlgorithmAES128CMAC
	TCPAOAlgorithmHMACSHA256MAC96
	TCPAOAlgorithmHMACSHA256MAC128
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

// ValidateTCPAOKeys checks a complete set of keys that is about to be installed
// on a socket. Callers that build a key set from user input should use it so
// that the same rules apply everywhere.
func ValidateTCPAOKeys(keys []TCPAOKey) error {
	if err := validateTCPAOKeyIDs(keys); err != nil {
		return err
	}
	for _, key := range keys {
		if len(key.MasterKey) == 0 || len(key.MasterKey) > TCPAOMaxKeyLen {
			return fmt.Errorf("TCP-AO key with SendID %d must contain 1-%d master-key bytes", key.SendID, TCPAOMaxKeyLen)
		}
		switch key.Algorithm {
		case TCPAOAlgorithmHMACSHA1, TCPAOAlgorithmAES128CMAC,
			TCPAOAlgorithmHMACSHA256MAC96, TCPAOAlgorithmHMACSHA256MAC128:
		default:
			return fmt.Errorf("unsupported TCP-AO algorithm for SendID %d", key.SendID)
		}
	}
	return nil
}

// validateTCPAOKeyIDs checks the key IDs only. RFC 5925 carries the KeyID in a
// single byte, so a key set cannot hold more than tcpAOKeyIDCount keys and the
// IDs must not repeat.
func validateTCPAOKeyIDs(keys []TCPAOKey) error {
	if len(keys) == 0 {
		return fmt.Errorf("TCP-AO requires at least one key")
	}
	if len(keys) > tcpAOKeyIDCount {
		return fmt.Errorf("TCP-AO supports at most %d keys per peer scope", tcpAOKeyIDCount)
	}
	var sendIDs, receiveIDs [tcpAOKeyIDCount]bool
	for _, key := range keys {
		if sendIDs[key.SendID] {
			return fmt.Errorf("duplicate TCP-AO SendID %d", key.SendID)
		}
		if receiveIDs[key.ReceiveID] {
			return fmt.Errorf("duplicate TCP-AO ReceiveID %d", key.ReceiveID)
		}
		sendIDs[key.SendID] = true
		receiveIDs[key.ReceiveID] = true
	}
	return nil
}
