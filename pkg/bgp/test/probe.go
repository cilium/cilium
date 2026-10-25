// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// TCPMD5SigAvailable probes whether TCP_MD5SIG option can be set on a server socket.
// Requires CONFIG_TCP_MD5SIG enabled in the kernel.
func TCPMD5SigAvailable() (bool, error) {
	var lc net.ListenConfig

	// Disable Multipath TCP to avoid "protocol not available" error on
	// kernels without MPTCP support.
	lc.SetMultipathTCP(false)

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		return false, fmt.Errorf("listen failed: %w", err)
	}
	defer listener.Close()

	fd, err := listener.(*net.TCPListener).File()
	if err != nil {
		return false, fmt.Errorf("error retrieving socket's file descriptor: %w", err)
	}
	defer fd.Close()

	err = unix.SetsockoptTCPMD5Sig(int(fd.Fd()), unix.IPPROTO_TCP, unix.TCP_MD5SIG, newTcpMD5Sig("1.2.3.4", "key"))
	if err != nil {
		if errors.Is(err, syscall.ENOPROTOOPT) {
			return false, nil // "protocol not available"
		}
		return false, fmt.Errorf("other error by setting setting socket option: %w", err)
	}
	return true, nil
}

// TCPAOAvailable probes whether the TCP_AO_ADD_KEY socket option can be set on a server socket.
// Requires Linux >= 6.7 with CONFIG_TCP_AO enabled in the kernel.
func TCPAOAvailable() (bool, error) {
	var lc net.ListenConfig

	// Disable Multipath TCP to avoid "protocol not available" error on
	// kernels without MPTCP support.
	lc.SetMultipathTCP(false)

	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	if err != nil {
		return false, fmt.Errorf("listen failed: %w", err)
	}
	defer listener.Close()

	fd, err := listener.(*net.TCPListener).File()
	if err != nil {
		return false, fmt.Errorf("error retrieving socket's file descriptor: %w", err)
	}
	defer fd.Close()

	err = unix.SetsockoptString(int(fd.Fd()), unix.IPPROTO_TCP, tcpAOAddKeyOption, string(newTCPAOAdd("1.2.3.4", "key")))
	if err != nil {
		if errors.Is(err, syscall.ENOPROTOOPT) {
			return false, nil // "protocol not available"
		}
		return false, fmt.Errorf("other error by setting setting socket option: %w", err)
	}
	return true, nil
}

// Linux TCP-AO UAPI constants (include/uapi/linux/tcp.h, Linux >= 6.7).
const (
	tcpAOAddKeyOption        = 38 // TCP_AO_ADD_KEY
	tcpAOSockaddrStorageSize = 128
	tcpAOAlgorithmNameSize   = 64
	tcpAOMACLength96         = 12
)

// tcpAOAdd mirrors Linux struct tcp_ao_add.
type tcpAOAdd struct {
	Address        [tcpAOSockaddrStorageSize]byte
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
	Key            [unix.TCP_AO_MAXKEYLEN]byte
}

// newTCPAOAdd builds a TCP_AO_ADD_KEY request for the given peer address, using the
// hmac(sha1) algorithm with a 96-bit MAC and the provided master key.
func newTCPAOAdd(address, key string) []byte {
	add := tcpAOAdd{
		MACLength: tcpAOMACLength96,
		SendID:    1,
		ReceiveID: 1,
		KeyLength: uint8(len(key)),
	}
	copy(add.Algorithm[:], "hmac(sha1)")
	copy(add.Key[:], key)

	addr := net.ParseIP(address)
	if addr.To4() != nil {
		sa := unix.RawSockaddrInet4{Family: unix.AF_INET}
		copy(sa.Addr[:], addr.To4())
		binary.Encode(add.Address[:], binary.NativeEndian, sa)
		add.PrefixLength = 32
	} else {
		sa := unix.RawSockaddrInet6{Family: unix.AF_INET6}
		copy(sa.Addr[:], addr.To16())
		binary.Encode(add.Address[:], binary.NativeEndian, sa)
		add.PrefixLength = 128
	}

	buf := make([]byte, binary.Size(add))
	binary.Encode(buf, binary.NativeEndian, add)
	return buf
}

func newTcpMD5Sig(address, key string) *unix.TCPMD5Sig {
	sig := &unix.TCPMD5Sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		sig.Addr.Family = unix.AF_INET
		copy(sig.Addr.Data[2:], addr.To4())
	} else {
		sig.Addr.Family = unix.AF_INET6
		copy(sig.Addr.Data[6:], addr.To16())
	}
	sig.Keylen = uint16(len(key))
	copy(sig.Key[0:], key)
	return sig
}
