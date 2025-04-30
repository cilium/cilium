// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// TCPMD5SigAvailable probes whether TCP_MD5SIG option can be set on a server socket.
// Requires CONFIG_TCP_MD5SIG enabled in the kernel.
func TCPMD5SigAvailable() (bool, error) {
	listener, err := net.Listen("tcp", "localhost:0")
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
