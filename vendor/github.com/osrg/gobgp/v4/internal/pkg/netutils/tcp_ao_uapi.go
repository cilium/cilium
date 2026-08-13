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
	"encoding/binary"
	"fmt"
	"net/netip"
)

// TCP-AO was added to the Linux UAPI in Linux 6.7.
// Its scalar fields use native byte order.
const (
	// Linux TCP-AO socket option numbers:
	// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L132-L135
	tcpAOAddKeyOption  = 38
	tcpAODelKeyOption  = 39
	tcpAOInfoOption    = 40
	tcpAOGetKeysOption = 41

	// tcpAOSockaddrStorageSize matches sizeof(struct __kernel_sockaddr_storage):
	// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/socket.h#L16-L27
	tcpAOSockaddrStorageSize = 128

	// tcpAOAlgorithmNameSize matches the alg_name fields in the Linux TCP-AO
	// UAPI structures:
	// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L369-L458
	tcpAOAlgorithmNameSize = 64

	// tcpAOKeyIDCount is the number of distinct values representable by an 8-bit TCP-AO key ID.
	// A listening socket can contain more keys when their peer scopes do not overlap.
	tcpAOKeyIDCount = 1 << 8

	// tcpAOAFInet and tcpAOAFInet6 match Linux AF_INET and AF_INET6:
	// https://github.com/torvalds/linux/blob/v6.7/include/linux/socket.h#L189-L200
	tcpAOAFInet  = 2
	tcpAOAFInet6 = 10

	// tcpAOKeyFlagIfindex and tcpAOKeyFlagExcludeOpt match Linux
	// TCP_AO_KEYF_IFINDEX and TCP_AO_KEYF_EXCLUDE_OPT:
	// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L371-L376
	tcpAOKeyFlagIfindex    = 1 << 0
	tcpAOKeyFlagExcludeOpt = 1 << 1

	// tcpAOMACLength is the 96-bit MAC length in bytes
	// specified for TCP-AO algorithms by RFC 5926, Section 3.2.
	// https://www.rfc-editor.org/rfc/rfc5926.html#section-3.2
	tcpAOMACLength = 12
)

// Linux C ABIs allocate the first declared bitfield from the low-order bit on
// little-endian systems and from the high-order bit on big-endian systems.
var (
	nativeIsBigEndian   = binary.NativeEndian.Uint16([]byte{1, 2}) == 0x0102
	tcpAOFlagSetCurrent = nativeCBitfield32Mask(0)
	tcpAOFlagSetRNext   = nativeCBitfield32Mask(1)
	tcpAOGetFlagCurrent = nativeCBitfield16Mask(0)
	tcpAOGetFlagRNext   = nativeCBitfield16Mask(1)
	tcpAOGetFlagAll     = nativeCBitfield16Mask(2)
)

func nativeCBitfield32Mask(fieldIndex uint) uint32 {
	if nativeIsBigEndian {
		return 1 << (31 - fieldIndex)
	}
	return 1 << fieldIndex
}

func nativeCBitfield16Mask(fieldIndex uint) uint16 {
	if nativeIsBigEndian {
		return 1 << (15 - fieldIndex)
	}
	return 1 << fieldIndex
}

// tcpAOSockaddrStorage mirrors Linux struct __kernel_sockaddr_storage:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/socket.h#L16-L27
type tcpAOSockaddrStorage [tcpAOSockaddrStorageSize]byte

// tcpAOAddABI mirrors Linux struct tcp_ao_add:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L378-L393
type tcpAOAddABI struct {
	Address        tcpAOSockaddrStorage
	Algorithm      [tcpAOAlgorithmNameSize]byte
	InterfaceIndex int32
	Flags          uint32
	Reserved2      uint16
	PrefixLength   uint8
	SendID         uint8
	ReceiveID      uint8
	MACLength      uint8
	KeyFlags       uint8
	KeyLength      uint8
	Key            [tcpAOMaxKeyLen]byte
}

// tcpAODelABI mirrors Linux struct tcp_ao_del:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L395-L409
type tcpAODelABI struct {
	Address        tcpAOSockaddrStorage
	InterfaceIndex int32
	Flags          uint32
	Reserved2      uint16
	PrefixLength   uint8
	SendID         uint8
	ReceiveID      uint8
	CurrentKey     uint8
	RNextKey       uint8
	KeyFlags       uint8
}

// tcpAOInfoABI mirrors Linux struct tcp_ao_info_opt:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L411-L427
type tcpAOInfoABI struct {
	Flags             uint32
	Reserved2         uint16
	CurrentKey        uint8
	RNextKey          uint8
	PacketGood        uint64
	PacketBad         uint64
	PacketKeyNotFound uint64
	PacketAORequired  uint64
	PacketDroppedICMP uint64
}

// tcpAOGetKeyABI mirrors Linux struct tcp_ao_getsockopt:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L429-L460
type tcpAOGetKeyABI struct {
	Address        tcpAOSockaddrStorage
	Algorithm      [tcpAOAlgorithmNameSize]byte
	Key            [tcpAOMaxKeyLen]byte
	KeyCount       uint32
	Flags          uint16
	SendID         uint8
	ReceiveID      uint8
	PrefixLength   uint8
	MACLength      uint8
	KeyFlags       uint8
	KeyLength      uint8
	InterfaceIndex int32
	PacketsGood    uint64
	PacketsBad     uint64
}

// tcpAOSockaddrInet4ABI mirrors Linux struct sockaddr_in:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/in.h#L256-L265
type tcpAOSockaddrInet4ABI struct {
	Family  uint16
	Port    [2]byte
	Address [4]byte
	Zero    [8]byte
}

// tcpAOSockaddrInet6ABI mirrors Linux struct sockaddr_in6:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/in6.h#L50-L56
type tcpAOSockaddrInet6ABI struct {
	Family   uint16
	Port     [2]byte
	FlowInfo [4]byte
	Address  [16]byte
	ScopeID  uint32
}

// tcpAOAlgorithmName returns a Linux TCP-AO algorithm name:
// https://github.com/torvalds/linux/blob/v7.2-rc1/net/ipv4/tcp_ao.c#L26-L42
func tcpAOAlgorithmName(algorithm TCPAOAlgorithm) string {
	switch algorithm {
	case TCPAOAlgorithmHMACSHA1:
		return "hmac(sha1)"
	case TCPAOAlgorithmAES128CMAC:
		return "cmac(aes128)"
	default:
		return ""
	}
}

func marshalTCPAOAdd(scope netip.Prefix, ifindex int32, key TCPAOKey, selected bool) ([]byte, error) {
	address, err := marshalTCPAOSockaddr(scope)
	if err != nil {
		return nil, err
	}
	abi := tcpAOAddABI{
		Address:        address,
		InterfaceIndex: ifindex,
		PrefixLength:   uint8(scope.Bits()),
		SendID:         key.SendID,
		ReceiveID:      key.ReceiveID,
		MACLength:      tcpAOMACLength,
		KeyLength:      uint8(len(key.MasterKey)),
	}
	copy(abi.Algorithm[:], tcpAOAlgorithmName(key.Algorithm))
	if selected {
		abi.Flags = tcpAOFlagSetCurrent | tcpAOFlagSetRNext
	}
	if ifindex != 0 {
		abi.KeyFlags |= tcpAOKeyFlagIfindex
	}
	if key.ExcludeTCPOptions {
		abi.KeyFlags |= tcpAOKeyFlagExcludeOpt
	}
	copy(abi.Key[:], key.MasterKey)
	return encodeTCPAOABI(&abi)
}

func marshalTCPAODel(scope netip.Prefix, ifindex int32, key TCPAOKey) ([]byte, error) {
	address, err := marshalTCPAOSockaddr(scope)
	if err != nil {
		return nil, err
	}
	abi := tcpAODelABI{
		Address:        address,
		InterfaceIndex: ifindex,
		PrefixLength:   uint8(scope.Bits()),
		SendID:         key.SendID,
		ReceiveID:      key.ReceiveID,
	}
	if ifindex != 0 {
		abi.KeyFlags = tcpAOKeyFlagIfindex
	}
	return encodeTCPAOABI(&abi)
}

func marshalTCPAOInfo(key *TCPAOKey, setRNext, setCurrent bool) ([]byte, error) {
	abi := tcpAOInfoABI{}
	if setRNext {
		abi.Flags = tcpAOFlagSetRNext
		abi.RNextKey = key.ReceiveID
	}
	if setCurrent {
		abi.Flags |= tcpAOFlagSetCurrent
		abi.CurrentKey = key.SendID
	}
	return encodeTCPAOABI(&abi)
}

func marshalTCPAOGetInfo() ([]byte, uint32, error) {
	buffer, err := encodeTCPAOABI(&tcpAOInfoABI{})
	if err != nil {
		return nil, 0, err
	}
	return buffer, uint32(len(buffer)), nil
}

func unmarshalTCPAOGetInfo(buffer []byte, size uint32) (TCPAOSocketCounters, error) {
	expectedSize := binary.Size(tcpAOInfoABI{})
	if size != uint32(expectedSize) {
		return TCPAOSocketCounters{}, fmt.Errorf("TCP-AO info size is %d, want %d", size, expectedSize)
	}
	var abi tcpAOInfoABI
	if _, err := binary.Decode(buffer[:size], binary.NativeEndian, &abi); err != nil {
		return TCPAOSocketCounters{}, fmt.Errorf("failed to decode TCP-AO info: %w", err)
	}
	return TCPAOSocketCounters{
		PacketsKeyNotFound: abi.PacketKeyNotFound,
		PacketsAORequired:  abi.PacketAORequired,
		PacketsDroppedICMP: abi.PacketDroppedICMP,
	}, nil
}

func marshalTCPAOGetKeys(keyCount uint32) ([]byte, uint32, error) {
	if keyCount == 0 {
		return nil, 0, fmt.Errorf("TCP-AO key state buffer requires at least one record")
	}
	request := tcpAOGetKeyABI{
		KeyCount: keyCount,
		Flags:    tcpAOGetFlagAll,
	}
	requestBytes, err := encodeTCPAOABI(&request)
	if err != nil {
		return nil, 0, err
	}
	buffer := make([]byte, int(keyCount)*len(requestBytes))
	copy(buffer, requestBytes)
	return buffer, uint32(len(requestBytes)), nil
}

func unmarshalTCPAOGetKeyCount(buffer []byte, recordSize uint32) (uint32, error) {
	expectedRecordSize := binary.Size(tcpAOGetKeyABI{})
	if recordSize != uint32(expectedRecordSize) {
		return 0, fmt.Errorf("TCP-AO key state record size is %d, need %d", recordSize, expectedRecordSize)
	}
	if len(buffer) < int(recordSize) {
		return 0, fmt.Errorf("TCP-AO key state buffer size is %d, need at least %d", len(buffer), recordSize)
	}

	var abi tcpAOGetKeyABI
	if _, err := binary.Decode(buffer[:recordSize], binary.NativeEndian, &abi); err != nil {
		return 0, fmt.Errorf("failed to decode TCP-AO key count: %w", err)
	}
	return abi.KeyCount, nil
}

func unmarshalTCPAOGetKeys(buffer []byte, recordSize, keyCount uint32) ([]TCPAOKeyState, error) {
	bufferCapacity := uint32(len(buffer) / int(recordSize))
	if keyCount > bufferCapacity {
		return nil, fmt.Errorf("TCP-AO key buffer capacity is %d keys, need %d keys", bufferCapacity, keyCount)
	}

	states := make([]TCPAOKeyState, 0, keyCount)
	for i := range keyCount {
		offset := i * recordSize
		var abi tcpAOGetKeyABI
		n, err := binary.Decode(buffer[offset:offset+recordSize], binary.NativeEndian, &abi)
		if err != nil {
			return nil, fmt.Errorf("failed to decode TCP-AO key state: %w", err)
		}
		if recordSize != uint32(n) {
			return nil, fmt.Errorf("decoded %d TCP-AO key state bytes, want %d", n, recordSize)
		}
		peer, err := unmarshalTCPAOSockaddr(abi.Address, abi.PrefixLength)
		if err != nil {
			return nil, fmt.Errorf("failed to decode TCP-AO key state peer: %w", err)
		}
		states = append(states, TCPAOKeyState{
			Peer:           peer,
			InterfaceIndex: abi.InterfaceIndex,
			SendID:         abi.SendID,
			ReceiveID:      abi.ReceiveID,
			Current:        abi.Flags&tcpAOGetFlagCurrent != 0,
			ReceiveNext:    abi.Flags&tcpAOGetFlagRNext != 0,
			PacketsGood:    abi.PacketsGood,
			PacketsBad:     abi.PacketsBad,
		})
	}
	return states, nil
}

func unmarshalTCPAOSockaddr(storage tcpAOSockaddrStorage, prefixLength uint8) (netip.Prefix, error) {
	switch family := binary.NativeEndian.Uint16(storage[:2]); family {
	case tcpAOAFInet:
		if prefixLength > 32 {
			return netip.Prefix{}, fmt.Errorf("invalid TCP-AO IPv4 prefix length %d", prefixLength)
		}
		var abi tcpAOSockaddrInet4ABI
		if _, err := binary.Decode(storage[:binary.Size(abi)], binary.NativeEndian, &abi); err != nil {
			return netip.Prefix{}, fmt.Errorf("failed to decode TCP-AO IPv4 address: %w", err)
		}
		return netip.PrefixFrom(netip.AddrFrom4(abi.Address), int(prefixLength)), nil
	case tcpAOAFInet6:
		if prefixLength > 128 {
			return netip.Prefix{}, fmt.Errorf("invalid TCP-AO IPv6 prefix length %d", prefixLength)
		}
		var abi tcpAOSockaddrInet6ABI
		if _, err := binary.Decode(storage[:binary.Size(abi)], binary.NativeEndian, &abi); err != nil {
			return netip.Prefix{}, fmt.Errorf("failed to decode TCP-AO IPv6 address: %w", err)
		}
		return netip.PrefixFrom(netip.AddrFrom16(abi.Address), int(prefixLength)), nil
	default:
		return netip.Prefix{}, fmt.Errorf("unsupported TCP-AO address family %d", family)
	}
}

func marshalTCPAOSockaddr(scope netip.Prefix) (tcpAOSockaddrStorage, error) {
	var storage tcpAOSockaddrStorage
	addr := scope.Addr()
	if addr.Is4() {
		abi := tcpAOSockaddrInet4ABI{
			Family:  tcpAOAFInet,
			Address: addr.As4(),
		}
		if err := encodeTCPAOSockaddr(&storage, &abi); err != nil {
			return storage, fmt.Errorf("failed to encode TCP-AO IPv4 address: %w", err)
		}
		return storage, nil
	}
	abi := tcpAOSockaddrInet6ABI{
		Family:  tcpAOAFInet6,
		Address: addr.As16(),
	}
	if err := encodeTCPAOSockaddr(&storage, &abi); err != nil {
		return storage, fmt.Errorf("failed to encode TCP-AO IPv6 address: %w", err)
	}
	return storage, nil
}

func encodeTCPAOSockaddr(storage *tcpAOSockaddrStorage, abi any) error {
	encoded, err := encodeTCPAOABI(abi)
	if err != nil {
		return err
	}
	if len(encoded) > len(storage) {
		return fmt.Errorf("TCP-AO socket address ABI record size is %d, maximum %d", len(encoded), len(storage))
	}
	copy(storage[:], encoded)
	return nil
}

func encodeTCPAOABI(abi any) ([]byte, error) {
	abiSize := binary.Size(abi)
	if abiSize < 0 {
		return nil, fmt.Errorf("TCP-AO ABI record has a variable-size field")
	}
	dst := make([]byte, abiSize)
	n, err := binary.Encode(dst, binary.NativeEndian, abi)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TCP-AO ABI record: %w", err)
	}
	if n != abiSize {
		return nil, fmt.Errorf("encoded %d TCP-AO ABI bytes, want %d", n, abiSize)
	}
	return dst, nil
}
