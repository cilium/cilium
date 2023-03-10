// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"strconv"
	"strings"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	hubbleDefaults "github.com/cilium/cilium/pkg/hubble/defaults"
)

// Peer represents a hubble peer.
type Peer struct {
	// Name is the name of the peer, typically the hostname. The name includes
	// the cluster name if a value other than default has been specified.
	// This value can be used to uniquely identify the host.
	// When the cluster name is not the default, the cluster name is prepended
	// to the peer name and a forward slash is added.
	//
	// Examples:
	//  - runtime1
	//  - testcluster/runtime1
	Name string

	// Target is the target of the peer's gRPC service.
	// See https://github.com/grpc/grpc/blob/master/doc/naming.md
	Target string

	// TLSEnabled indicates whether the service offered by the peer has TLS
	// enabled.
	TLSEnabled bool

	// TLSServerName is the name the TLS certificate should be matched to.
	TLSServerName string
}

// FromChangeNotification creates a new Peer from a ChangeNotification.
func FromChangeNotification(cn *peerpb.ChangeNotification) *Peer {
	if cn == nil {
		return (*Peer)(nil)
	}
	target := cn.GetAddress()
	// A file path referencing a unix socket, prepend the unix:// scheme
	if strings.HasPrefix(target, "/") && strings.HasSuffix(target, ".sock") {
		target = "unix://" + target
	}

	// If it's a non-socket, check that it has the port specified
	if !strings.HasPrefix(target, "unix://") {
		_, _, err := net.SplitHostPort(target)
		// Error indicates no port specified, add the default port
		if err != nil {
			if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
				target = net.JoinHostPort(target, strconv.Itoa(hubbleDefaults.ServerPort))
			}
		}
	}

	var tlsEnabled bool
	var tlsServerName string
	if tls := cn.GetTls(); tls != nil {
		tlsEnabled = true
		tlsServerName = tls.GetServerName()
	}
	return &Peer{
		Name:          cn.GetName(),
		Target:        target,
		TLSEnabled:    tlsEnabled,
		TLSServerName: tlsServerName,
	}
}

// String implements fmt's Stringer interface.
func (p Peer) String() string {
	return p.Name
}
