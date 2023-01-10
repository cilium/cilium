// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"strconv"
	"strings"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/defaults"
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

	// Address is the address of the peer's gRPC service.
	Address net.Addr

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
	var err error
	var addr net.Addr
	switch a := cn.GetAddress(); {
	case strings.HasPrefix(a, "unix://"), strings.HasPrefix(a, "/") && strings.HasSuffix(a, ".sock"):
		addr, err = net.ResolveUnixAddr("unix", a)
	case a == "":
		// no address specified, leave it nil
	default:
		var host, port string
		if host, port, err = net.SplitHostPort(a); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				var p int
				if p, err = strconv.Atoi(port); err == nil {
					addr = &net.TCPAddr{
						IP:   ip,
						Port: p,
					}
				} else {
					err = nil
					addr = &net.TCPAddr{
						IP:   ip,
						Port: defaults.ServerPort,
					}
				}
			} else {
				// resolve then
				addr, err = net.ResolveTCPAddr("tcp", a)
			}
		} else if ip := net.ParseIP(a); ip != nil {
			err = nil
			addr = &net.TCPAddr{
				IP:   ip,
				Port: defaults.ServerPort,
			}
		}
	}
	if err != nil {
		addr = (net.Addr)(nil)
	}
	var tlsEnabled bool
	var tlsServerName string
	if tls := cn.GetTls(); tls != nil {
		tlsEnabled = true
		tlsServerName = tls.GetServerName()
	}
	return &Peer{
		Name:          cn.GetName(),
		Address:       addr,
		TLSEnabled:    tlsEnabled,
		TLSServerName: tlsServerName,
	}
}

// String implements fmt's Stringer interface.
func (p Peer) String() string {
	return p.Name
}
