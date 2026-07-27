//go:build !linux
// +build !linux

package netlink

import (
	"net"
)

func SocketGet(local, remote net.Addr) (*Socket, error) {
	return nil, ErrNotImplemented
}

func SocketDestroy(local, remote net.Addr) error {
	return ErrNotImplemented
}

func SocketDiagTCPInfo(family uint8) ([]*InetDiagTCPInfoResp, error) {
	return nil, ErrNotImplemented
}

func SocketDiagTCP(family uint8) ([]*Socket, error) {
	return nil, ErrNotImplemented
}

func SocketDiagUDPInfo(family uint8) ([]*InetDiagUDPInfoResp, error) {
	return nil, ErrNotImplemented
}

func SocketDiagUDP(family uint8) ([]*Socket, error) {
	return nil, ErrNotImplemented
}

func UnixSocketDiagInfo() ([]*UnixDiagInfoResp, error) {
	return nil, ErrNotImplemented
}

func UnixSocketDiag() ([]*UnixSocket, error) {
	return nil, ErrNotImplemented
}
