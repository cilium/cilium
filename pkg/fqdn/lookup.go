// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net"
)

// DNSIPRecords mimics the RR data from an A or AAAA response.
// My kingdom for a DNS IP RR type that isn't hidden in the stdlib or has a
// million layers of type indirection.
type DNSIPRecords struct {
	// TTL is the time, in seconds, that these IPs are valid for
	TTL int

	// IPs are the IPs associated with a DNS Name
	IPs []net.IP
}
