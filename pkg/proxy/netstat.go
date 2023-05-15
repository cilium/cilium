// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"bytes"
	"os"
	"regexp"
	"strconv"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// procNetTCPFiles is the constant list of /proc/net files to read to get
	// the same information about open TCP connections as output by netstat.
	procNetTCPFiles = []string{
		"/proc/net/tcp",
		"/proc/net/tcp6",
	}

	// procNetUDPFiles is the constant list of /proc/net files to read to get
	// the same information about open UDP connections as output by netstat.
	procNetUDPFiles = []string{
		"/proc/net/udp",
		"/proc/net/udp6",
	}

	// procNetFileRegexp matches the first two columns of /proc/net/{tcp,udp}*
	// files and submatches on the local port number.
	procNetFileRegexp = regexp.MustCompile("^ *[[:digit:]]*: *[[:xdigit:]]*:([[:xdigit:]]*) ")
)

// readOpenLocalPorts returns the set of L4 ports currently open locally.
// procNetFiles should be procNetTCPFiles or procNetUDPFiles (or both).
func readOpenLocalPorts(procNetFiles []string) map[uint16]struct{} {
	openLocalPorts := make(map[uint16]struct{}, 128)

	for _, file := range procNetFiles {
		b, err := os.ReadFile(file)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, file).Errorf("cannot read proc file")
			continue
		}

		lines := bytes.Split(b, []byte("\n"))

		// Extract the local port number from the "local_address" column.
		// The header line won't match and will be ignored.
		for _, line := range lines {
			groups := procNetFileRegexp.FindSubmatch(line)
			if len(groups) != 2 { // no match
				continue
			}
			// The port number is in hexadecimal.
			localPort, err := strconv.ParseUint(string(groups[1]), 16, 16)
			if err != nil {
				log.WithError(err).WithField(logfields.Path, file).Errorf("cannot read proc file")
				continue
			}
			openLocalPorts[uint16(localPort)] = struct{}{}
		}
	}

	return openLocalPorts
}

// OpenLocalPorts returns the set of L4 ports currently open locally.
func OpenLocalPorts() map[uint16]struct{} {
	return readOpenLocalPorts(append(procNetTCPFiles, procNetUDPFiles...))
}
