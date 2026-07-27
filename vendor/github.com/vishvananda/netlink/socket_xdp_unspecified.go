//go:build !linux
// +build !linux

package netlink

func SocketXDPGetInfo(ino uint32, cookie uint64) (*XDPDiagInfoResp, error) {
	return nil, ErrNotImplemented
}

func SocketDiagXDP() ([]*XDPDiagInfoResp, error) {
	return nil, ErrNotImplemented
}
