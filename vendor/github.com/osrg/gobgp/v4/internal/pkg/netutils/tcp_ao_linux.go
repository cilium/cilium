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

//go:build linux

package netutils

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// AddTCPAOKeysSockopt installs all provided keys on a TCP socket.
// A nil PreferredSendID leaves the existing CurrentKey and RNextKey selection unchanged,
// as required when installing keys on a listening socket. A non-nil value selects the matching key.
func AddTCPAOKeysSockopt(sc syscall.RawConn, peer netip.Prefix, interfaceName string, config TCPAOConfig) error {
	vrfIfIndex, err := vrfInterfaceIndex(interfaceName)
	if err != nil {
		return err
	}
	if err := validateTCPAOPeerScope(peer, vrfIfIndex); err != nil {
		return err
	}
	if err := validateTCPAOAddKeys(config.Keys); err != nil {
		return err
	}
	preferredKey, err := getPreferredTCPAOKey(config)
	if err != nil {
		return err
	}
	for _, key := range config.Keys {
		command, err := marshalTCPAOAdd(peer, vrfIfIndex, key, preferredKey != nil && preferredKey.SendID == key.SendID)
		if err != nil {
			return err
		}
		if err := setTCPAOSockopt(sc, tcpAOAddKeyOption, command); err != nil {
			return fmt.Errorf("failed to add TCP-AO key SendID %d ReceiveID %d: %w", key.SendID, key.ReceiveID, err)
		}
	}
	return nil
}

// DeleteTCPAOKeysSockopt removes all configured keys from a TCP socket.
func DeleteTCPAOKeysSockopt(sc syscall.RawConn, peer netip.Prefix, interfaceName string, config TCPAOConfig) error {
	vrfIfIndex, err := vrfInterfaceIndex(interfaceName)
	if err != nil {
		return err
	}
	if err := validateTCPAOPeerScope(peer, vrfIfIndex); err != nil {
		return err
	}
	if err := validateTCPAOKeyIDs(config.Keys); err != nil {
		return err
	}
	for _, key := range config.Keys {
		command, err := marshalTCPAODel(peer, vrfIfIndex, key)
		if err != nil {
			return err
		}
		if err := setTCPAOSockopt(sc, tcpAODelKeyOption, command); err != nil {
			return fmt.Errorf("failed to delete TCP-AO key SendID %d ReceiveID %d: %w", key.SendID, key.ReceiveID, err)
		}
	}
	return nil
}

// SetTCPAOKeySockopt sets CurrentKey and/or RNextKey to the key selected by PreferredSendID on a connected TCP-AO socket.
func SetTCPAOKeySockopt(sc syscall.RawConn, config TCPAOConfig, setRNext, setCurrent bool) error {
	if err := validateTCPAOKeyIDs(config.Keys); err != nil {
		return err
	}
	preferredKey, err := getPreferredTCPAOKey(config)
	if err != nil {
		return err
	}
	if preferredKey == nil {
		return fmt.Errorf("TCP-AO key selection requires PreferredSendID")
	}
	command, err := marshalTCPAOInfo(preferredKey, setRNext, setCurrent)
	if err != nil {
		return err
	}
	if err := setTCPAOSockopt(sc, tcpAOInfoOption, command); err != nil {
		return fmt.Errorf("failed to select TCP-AO key %d: %w", *config.PreferredSendID, err)
	}
	return nil
}

// GetTCPAOKeyStateSockopt returns the keys installed on a TCP-AO socket and their kernel-maintained operational state.
func GetTCPAOKeyStateSockopt(sc syscall.RawConn) ([]TCPAOKeyState, error) {
	// Initially allocate one record for every possible key ID.
	// The kernel reports the total matching count, so larger listener key sets will be retried with larger capacity.
	keyCapacity := uint32(tcpAOKeyIDCount)
	for {
		buffer, length, err := marshalTCPAOGetKeys(keyCapacity)
		if err != nil {
			return nil, err
		}
		if err := getTCPAOSockopt(sc, tcpAOGetKeysOption, buffer, &length); err != nil {
			clear(buffer)
			return nil, fmt.Errorf("failed to get TCP-AO keys: %w", err)
		}
		keyCount, err := unmarshalTCPAOGetKeyCount(buffer, length)
		if err != nil {
			clear(buffer)
			return nil, err
		}
		if keyCount > keyCapacity {
			clear(buffer)
			keyCapacity = keyCount
			continue // retry with larger capacity fitting the actual key count
		}
		states, err := unmarshalTCPAOGetKeys(buffer, length, keyCount)
		clear(buffer)
		return states, err
	}
}

// GetTCPAOSocketCountersSockopt returns the operational counters maintained for a TCP-AO socket.
func GetTCPAOSocketCountersSockopt(sc syscall.RawConn) (TCPAOSocketCounters, error) {
	buffer, length, err := marshalTCPAOGetInfo()
	if err != nil {
		return TCPAOSocketCounters{}, err
	}
	if err := getTCPAOSockopt(sc, tcpAOInfoOption, buffer, &length); err != nil {
		return TCPAOSocketCounters{}, fmt.Errorf("failed to get TCP-AO info: %w", err)
	}
	return unmarshalTCPAOGetInfo(buffer, length)
}

// vrfInterfaceIndex returns the VRF interface index used to scope a TCP-AO key.
// It accepts either the VRF device or one of its enslaved devices.
func vrfInterfaceIndex(interfaceName string) (int32, error) {
	if interfaceName == "" {
		return 0, nil
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return 0, fmt.Errorf("failed to get link for interface %s: %w", interfaceName, err)
	}
	if link.Type() != "vrf" {
		masterIndex := link.Attrs().MasterIndex
		if masterIndex == 0 {
			return 0, nil
		}
		link, err = netlink.LinkByIndex(masterIndex)
		if err != nil {
			return 0, fmt.Errorf("failed to get master link for interface %s: %w", interfaceName, err)
		}
		if link.Type() != "vrf" {
			return 0, nil
		}
	}
	return int32(link.Attrs().Index), nil
}

func validateTCPAOPeerScope(prefix netip.Prefix, ifIndex int32) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid TCP-AO peer scope")
	}
	if ifIndex < 0 {
		return fmt.Errorf("invalid TCP-AO interface index %d", ifIndex)
	}
	addr := prefix.Addr()
	if addr.Zone() != "" {
		return fmt.Errorf("TCP-AO peer scope must not contain an IPv6 zone")
	}
	if addr.Is4In6() {
		return fmt.Errorf("TCP-AO peer scope must use an unmapped IPv4 address")
	}
	if prefix != prefix.Masked() {
		return fmt.Errorf("TCP-AO peer scope %s has host bits set", prefix)
	}
	if prefix.Bits() != 0 && addr.IsUnspecified() {
		return fmt.Errorf("TCP-AO unspecified peer address requires a zero-length prefix")
	}
	return nil
}

func validateTCPAOAddKeys(keys []TCPAOKey) error {
	if err := validateTCPAOKeyIDs(keys); err != nil {
		return err
	}
	for _, key := range keys {
		if len(key.MasterKey) == 0 || len(key.MasterKey) > tcpAOMaxKeyLen {
			return fmt.Errorf("TCP-AO key with SendID %d must contain 1-%d master-key bytes", key.SendID, tcpAOMaxKeyLen)
		}
		switch key.Algorithm {
		case TCPAOAlgorithmHMACSHA1, TCPAOAlgorithmAES128CMAC:
		default:
			return fmt.Errorf("unsupported TCP-AO algorithm for SendID %d", key.SendID)
		}
	}
	return nil
}

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

func getPreferredTCPAOKey(config TCPAOConfig) (*TCPAOKey, error) {
	if config.PreferredSendID == nil {
		return nil, nil
	}
	for i := range config.Keys {
		if config.Keys[i].SendID == *config.PreferredSendID {
			return &config.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("TCP-AO preferred SendID %d does not exist", *config.PreferredSendID)
}

func setTCPAOSockopt(sc syscall.RawConn, option int, value []byte) error {
	var sockerr error
	controlErr := sc.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_TCP),
			uintptr(option),
			uintptr(unsafe.Pointer(&value[0])),
			uintptr(len(value)),
			0,
		)
		if errno != 0 {
			sockerr = os.NewSyscallError("setsockopt(TCP_AO)", errno)
		}
	})
	runtime.KeepAlive(value)
	if sockerr != nil {
		return sockerr
	}
	return controlErr
}

func getTCPAOSockopt(sc syscall.RawConn, option int, value []byte, length *uint32) error {
	var sockerr error
	controlErr := sc.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_TCP),
			uintptr(option),
			uintptr(unsafe.Pointer(&value[0])),
			uintptr(unsafe.Pointer(length)),
			0,
		)
		if errno != 0 {
			sockerr = os.NewSyscallError("getsockopt(TCP_AO)", errno)
		}
	})
	runtime.KeepAlive(value)
	runtime.KeepAlive(length)
	if sockerr != nil {
		return sockerr
	}
	return controlErr
}
