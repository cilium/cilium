// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// xdpLinkAttachFailedTracepoint is the kernel tracepoint (Linux 6.6+) that
	// fires with the netlink extack message when attaching an XDP program via
	// BPF_LINK_CREATE fails. See bpf/bpf_xdp_attach_error.c for details.
	xdpLinkAttachFailedTracepoint = "bpf_xdp_link_attach_failed"

	xdpAttachErrorMapName  = "cilium_xdp_attach_err"
	xdpAttachErrorProgName = "xdp_attach_failed"

	// xdpAttachErrorLen must match XDP_ATTACH_ERROR_LEN in
	// bpf/bpf_xdp_attach_error.c.
	xdpAttachErrorLen = 256
)

// xdpAttachErrorValue mirrors struct xdp_attach_error in
// bpf/bpf_xdp_attach_error.c.
type xdpAttachErrorValue struct {
	Msg [xdpAttachErrorLen]byte
}

// xdpAttachErrorCapture installs a raw tracepoint program that records the
// kernel's verbose XDP attach error message into a map, so the loader can
// surface it when BPF_LINK_CREATE fails with an opaque errno.
//
// Capture is best-effort: on kernels older than 6.6 (where the tracepoint does
// not exist) or when the program can't be loaded/attached, the capture is
// simply unavailable and message() returns an empty string.
type xdpAttachErrorCapture struct {
	// lnk keeps the tracepoint attachment (and thus the program) alive. The
	// kernel keeps the program loaded as long as this link exists, so there's
	// no need to also retain the owning collection.
	lnk link.Link
	// errs is the map the program writes captured messages into. We own it
	// (detached from the collection) and close it in Close().
	errs *ebpf.Map
}

// newXDPAttachErrorCapture loads and attaches the capture program. It always
// returns a non-nil value so callers don't need nil checks; when capture is
// unavailable, the returned value's methods are no-ops.
func newXDPAttachErrorCapture(logger *slog.Logger) *xdpAttachErrorCapture {
	capture := &xdpAttachErrorCapture{}

	spec, err := bpfgen.LoadXDPAttachError()
	if err != nil {
		logger.Debug("XDP attach error capture unavailable: loading spec failed",
			logfields.Error, err)
		return capture
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		logger.Debug("XDP attach error capture unavailable: loading collection failed",
			logfields.Error, err)
		return capture
	}

	prog := coll.Programs[xdpAttachErrorProgName]
	if prog == nil {
		logger.Debug("XDP attach error capture unavailable: program not found in collection")
		coll.Close()
		return capture
	}

	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    xdpLinkAttachFailedTracepoint,
		Program: prog,
	})
	if err != nil {
		// The tracepoint was added in Linux 6.6; on older kernels attaching
		// returns ENOENT. Treat any failure as "capture unavailable".
		logger.Debug("XDP attach error capture unavailable: attaching tracepoint failed (kernel older than 6.6?)",
			logfields.Error, err)
		coll.Close()
		return capture
	}

	// Take ownership of the map (so coll.Close() won't free it), then release
	// the rest of the collection. The program's userspace fd is closed here,
	// but the kernel keeps it loaded via the link we hold in capture.lnk.
	capture.errs = coll.DetachMap(xdpAttachErrorMapName)
	capture.lnk = lnk
	coll.Close()
	return capture
}

// message returns the kernel error message captured for the most recent failed
// XDP attach, or an empty string if none was recorded or capture is
// unavailable.
func (c *xdpAttachErrorCapture) message() string {
	if c == nil || c.errs == nil {
		return ""
	}

	var (
		key uint32
		val xdpAttachErrorValue
	)
	if err := c.errs.Lookup(&key, &val); err != nil {
		return ""
	}
	return unix.ByteSliceToString(val.Msg[:])
}

// Close detaches the tracepoint (unloading the program) and releases the map.
func (c *xdpAttachErrorCapture) Close() {
	if c == nil {
		return
	}
	if c.lnk != nil {
		c.lnk.Close()
		c.lnk = nil
	}
	if c.errs != nil {
		c.errs.Close()
		c.errs = nil
	}
}
