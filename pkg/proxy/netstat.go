package proxy

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

var (
	// procNetTcpFiles is the constant list of /proc/net files to read to get
	// the same information about open TCP connections as output by netstat.
	procNetTcpFiles []string = []string{
		"/proc/net/tcp",
		"/proc/net/tcp6",
	}

	// procNetTcpRegexp matches the first two columns of /proc/net/tcp* files
	// and submatches on the local port number.
	procNetTcpRegexp *regexp.Regexp = regexp.MustCompile("^ *[[:digit:]]*: *[[:xdigit:]]*:([[:xdigit:]]*) ")
)

// readOpenLocalPorts returns the set of TCP ports currently open locally.
func readOpenLocalPorts() (map[uint16]struct{}, error) {
	openLocalPorts := make(map[uint16]struct{}, 128)

	for _, file := range procNetTcpFiles {
		bytes, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("cannot read proc file %s: %s", file, err)
		}
		lines := strings.Split(string(bytes), "\n")

		// Extract the local port number from the "local_address" column.
		// The header line won't match and will be ignored.
		for _, line := range lines {
			groups := procNetTcpRegexp.FindStringSubmatch(line)
			if len(groups) != 2 { // no match
				continue
			}
			// The port number is in hexadecimal.
			localPort, err := strconv.ParseUint(groups[1], 16, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid local port number in %s: %s", file, err)
			}
			openLocalPorts[uint16(localPort)] = struct{}{}
		}
	}

	return openLocalPorts, nil
}
