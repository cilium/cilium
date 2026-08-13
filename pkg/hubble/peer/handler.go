// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"net"
	"strconv"
	"strings"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/node/types"
)

// handler turns node table changes into peerpb.ChangeNotifications. As C is
// unbuffered, clients must be ready to read from it before processing changes.
// Once not used anymore, Close must be called to free resources.
type handler struct {
	stop        chan struct{}
	C           chan *peerpb.ChangeNotification
	tls         bool
	addressPref serviceoption.AddressFamilyPreference
	hubblePort  int
}

func newHandler(withoutTLSInfo bool, addressPref serviceoption.AddressFamilyPreference, hubblePort int) *handler {
	return &handler{
		stop:        make(chan struct{}),
		C:           make(chan *peerpb.ChangeNotification),
		tls:         !withoutTLSInfo,
		addressPref: addressPref,
		hubblePort:  hubblePort,
	}
}

func (h *handler) nodeAdded(n types.Node) {
	cn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_ADDED)
	select {
	case h.C <- cn:
	case <-h.stop:
	}
}

func (h *handler) nodeUpdated(o, n types.Node) {
	oAddr, nAddr := nodeAddress(o, h.addressPref), nodeAddress(n, h.addressPref)
	if o.Fullname() == n.Fullname() {
		if oAddr.String() == nAddr.String() {
			// this corresponds to the same peer
			// => no need to send a notification
			return
		}
		cn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_UPDATED)
		select {
		case h.C <- cn:
		case <-h.stop:
		}
		return
	}
	// the name has changed; from a service consumer perspective, this is the
	// same as if the peer with the old name was removed and a new one added
	ocn := h.newChangeNotification(o, peerpb.ChangeNotificationType_PEER_DELETED)
	select {
	case h.C <- ocn:
	case <-h.stop:
		return
	}
	ncn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_ADDED)
	select {
	case h.C <- ncn:
	case <-h.stop:
	}
}

func (h *handler) nodeDeleted(n types.Node) {
	cn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_DELETED)
	select {
	case h.C <- cn:
	case <-h.stop:
	}
}

// Close frees handler resources.
func (h *handler) Close() {
	close(h.stop)
}

// newChangeNotification creates a new change notification with the provided
// information. If withTLS is true, the TLS field is populated with the server
// name derived from the node and cluster names.
func (h *handler) newChangeNotification(n types.Node, t peerpb.ChangeNotificationType) *peerpb.ChangeNotification {
	var tls *peerpb.TLS
	if h.tls {
		tls = &peerpb.TLS{
			ServerName: TLSServerName(n.Name, n.Cluster),
		}
	}

	addr := ""
	if ip := nodeAddress(n, h.addressPref); ip != nil {
		addr = ip.String()
		if h.hubblePort != 0 {
			addr = net.JoinHostPort(addr, strconv.Itoa(h.hubblePort))
		}
	}

	return &peerpb.ChangeNotification{
		Name:    n.Fullname(),
		Address: addr,
		Type:    t,
		Tls:     tls,
	}
}

// nodeAddress returns the node's address. If the node has both IPv4 and IPv6
// addresses, pref controls which address type is returned.
func nodeAddress(n types.Node, pref serviceoption.AddressFamilyPreference) net.IP {
	for _, family := range pref {
		switch family {
		case serviceoption.AddressFamilyIPv4:
			if addr := n.GetNodeIP(false); addr.To4() != nil {
				return addr
			}
		case serviceoption.AddressFamilyIPv6:
			if addr := n.GetNodeIP(true); addr.To4() == nil {
				return addr
			}
		}
	}
	return nil
}

// TLSServerName constructs a server name to be used as the TLS server name.
// The server name is of the following form:
//
//	<nodeName>.<clusterName>.<hubble-grpc-svc-name>.<domain>
//
// For example, with nodeName=moseisley and clusterName=tatooine, the following
// server name is returned:
//
//	moseisley.tatooine.hubble-grpc.cilium.io
//
// When nodeName is not provided, an empty string is returned. All Dot (.) in
// nodeName are replaced by Hyphen (-). When clusterName is not provided, it
// defaults to the default cluster name. All Dot (.) in clusterName are
// replaced by Hypen (-).
func TLSServerName(nodeName, clusterName string) string {
	if nodeName == "" {
		return ""
	}
	// To ensure that each node's ServerName is at the same DNS domain level,
	// we have to lookout for Dot (.) as Kubernetes allows them in Node names.
	nn := strings.ReplaceAll(nodeName, ".", "-")
	if clusterName == "" {
		clusterName = ciliumDefaults.ClusterName
	}
	// The cluster name may also contain dots.
	cn := strings.ReplaceAll(clusterName, ".", "-")
	return strings.Join([]string{
		nn,
		cn,
		defaults.GRPCServiceName,
		defaults.DomainName,
	}, ".")
}
