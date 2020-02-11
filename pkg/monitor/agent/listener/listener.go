// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package listener

import (
	"net"
	"os"

	"github.com/cilium/cilium/pkg/monitor/payload"

	"golang.org/x/sys/unix"
)

// Version is the version of a node-monitor listener client. There are
// two API versions:
// - 1.0 which encodes the gob type information with each payload sent, and
//   adds a meta object before it.
// - 1.2 which maintains a gob session per listener, thus only encoding the
//   type information on the first payload sent. It does NOT prepend the a meta
//   object.
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

	op, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	syscerr, ok := op.Err.(*os.SyscallError)
	if !ok {
		return false
	}

	errn := syscerr.Err.(unix.Errno)
	return errn == unix.EPIPE
}
