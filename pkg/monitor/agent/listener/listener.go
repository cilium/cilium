// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package listener

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/monitor/payload"
)

// Version is the version of a node-monitor listener client. There are
// two API versions:
//   - 1.0 which encodes the gob type information with each payload sent, and
//     adds a meta object before it.
//   - 1.2 which maintains a gob session per listener, thus only encoding the
//     type information on the first payload sent. It does NOT prepend the a meta
//     object.
type Version string

const (
	// VersionUnsupported is here for use in error returns etc.
	VersionUnsupported = Version("unsupported")

	// Version1_2 is the API 1.0 version of the protocol (see above).
	Version1_2 = Version("1.2")
)

// MonitorListener is a generic consumer of monitor events. Implementers are
// expected to handle errors as needed, including exiting.
type MonitorListener interface {
	// Enqueue adds this payload to the send queue. Any errors should be logged
	// and handled appropriately.
	Enqueue(pl *payload.Payload)

	// Version returns the API version of this listener
	Version() Version

	// Close closes the listener.
	Close()
}

// IsDisconnected is a convenience function that wraps the absurdly long set of
// checks for a disconnect.
func IsDisconnected(err error) bool {
	if err == nil {
		return false
	}

	op := &net.OpError{}
	if !errors.As(err, &op) {
		return false
	}

	syscerr := &os.SyscallError{}
	if !errors.As(op.Err, &syscerr) {
		return false
	}

	var errn unix.Errno
	return errors.As(syscerr.Err, &errn) && errors.Is(errn, unix.EPIPE)
}
