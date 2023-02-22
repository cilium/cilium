//go:build linux
// +build linux

package socket

import (
	"os"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// IoctlKCMClone wraps ioctl(2) for unix.KCMClone values, but returns a Conn
// rather than a raw file descriptor.
func (c *Conn) IoctlKCMClone() (*Conn, error) {
	const op = "ioctl"

	var (
		info *unix.KCMClone
		err  error
	)

	doErr := c.control(op, func(fd int) error {
		info, err = unix.IoctlKCMClone(fd)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		return nil, os.NewSyscallError(op, err)
	}

	// Successful clone, wrap in a Conn for use by the caller.
	return New(int(info.Fd), c.name)
}

// IoctlKCMAttach wraps ioctl(2) for unix.KCMAttach values.
func (c *Conn) IoctlKCMAttach(info unix.KCMAttach) error {
	return c.controlErr("ioctl", func(fd int) error {
		return unix.IoctlKCMAttach(fd, info)
	})
}

// IoctlKCMUnattach wraps ioctl(2) for unix.KCMUnattach values.
func (c *Conn) IoctlKCMUnattach(info unix.KCMUnattach) error {
	return c.controlErr("ioctl", func(fd int) error {
		return unix.IoctlKCMUnattach(fd, info)
	})
}

// PidfdGetfd wraps pidfd_getfd(2) for a Conn which wraps a pidfd, but returns a
// Conn rather than a raw file descriptor.
func (c *Conn) PidfdGetfd(targetFD, flags int) (*Conn, error) {
	const op = "pidfd_getfd"

	var (
		outFD int
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		outFD, err = unix.PidfdGetfd(fd, targetFD, flags)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		return nil, os.NewSyscallError(op, err)
	}

	// Successful getfd, wrap in a Conn for use by the caller.
	return New(outFD, c.name)
}

// PidfdSendSignal wraps pidfd_send_signal(2) for a Conn which wraps a Linux
// pidfd.
func (c *Conn) PidfdSendSignal(sig unix.Signal, info *unix.Siginfo, flags int) error {
	return c.controlErr("pidfd_send_signal", func(fd int) error {
		return unix.PidfdSendSignal(fd, sig, info, flags)
	})
}

// SetBPF attaches an assembled BPF program to a Conn.
func (c *Conn) SetBPF(filter []bpf.RawInstruction) error {
	// We can't point to the first instruction in the array if no instructions
	// are present.
	if len(filter) == 0 {
		return os.NewSyscallError("setsockopt", unix.EINVAL)
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	return c.SetsockoptSockFprog(unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

// RemoveBPF removes a BPF filter from a Conn.
func (c *Conn) RemoveBPF() error {
	// 0 argument is ignored.
	return c.SetsockoptInt(unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
}

// SetsockoptPacketMreq wraps setsockopt(2) for unix.PacketMreq values.
func (c *Conn) SetsockoptPacketMreq(level, opt int, mreq *unix.PacketMreq) error {
	return c.controlErr("setsockopt", func(fd int) error {
		return unix.SetsockoptPacketMreq(fd, level, opt, mreq)
	})
}

// SetsockoptSockFprog wraps setsockopt(2) for unix.SockFprog values.
func (c *Conn) SetsockoptSockFprog(level, opt int, fprog *unix.SockFprog) error {
	return c.controlErr("setsockopt", func(fd int) error {
		return unix.SetsockoptSockFprog(fd, level, opt, fprog)
	})
}

// GetSockoptTpacketStats wraps getsockopt(2) for getting TpacketStats
func (c *Conn) GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error) {
	const op = "getsockopt"

	var (
		stats *unix.TpacketStats
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		stats, err = unix.GetsockoptTpacketStats(fd, level, name)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}

	return stats, os.NewSyscallError(op, err)
}

// GetSockoptTpacketStatsV3 wraps getsockopt(2) for getting TpacketStatsV3
func (c *Conn) GetSockoptTpacketStatsV3(level, name int) (*unix.TpacketStatsV3, error) {
	const op = "getsockopt"

	var (
		stats *unix.TpacketStatsV3
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		stats, err = unix.GetsockoptTpacketStatsV3(fd, level, name)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}

	return stats, os.NewSyscallError(op, err)
}
