// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"strings"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/node/types"
)

// handler implements the datapath.NodeHandler interface so that it can be
// subscribed to a node manager and receives update about nodes being
// added/updated/deleted. Node update information is turned into
// peerpb.ChangeNotification and sent to the channel C. As this channel is
// unbuffered, clients must be ready to read from it before subscribing the
// handler to the node manager.
// Once not used anymore, Close must be called to free resources.
type handler struct {
	stop        chan struct{}
	C           chan *peerpb.ChangeNotification
	tls         bool
	addressPref serviceoption.AddressFamilyPreference
}

func newHandler(withoutTLSInfo bool, addressPref serviceoption.AddressFamilyPreference) *handler {
	return &handler{
		stop:        make(chan struct{}),
		C:           make(chan *peerpb.ChangeNotification),
		tls:         !withoutTLSInfo,
		addressPref: addressPref,
	}
}

// Ensure that Service implements the NodeHandler interface so that it can be
// notified of nodes updates by the daemon's node manager.
var _ datapath.NodeHandler = (*handler)(nil)

// NodeAdd implements datapath.NodeHandler.NodeAdd.
func (h *handler) NodeAdd(n types.Node) error {
	cn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_ADDED)
	select {
	case h.C <- cn:
	case <-h.stop:
	}
	return nil
}

// NodeUpdate implements datapath.NodeHandler.NodeUpdate.
func (h *handler) NodeUpdate(o, n types.Node) error {
	oAddr, nAddr := nodeAddress(o, h.addressPref), nodeAddress(n, h.addressPref)
	if o.Fullname() == n.Fullname() {
		if oAddr == nAddr {
			// this corresponds to the same peer
			// => no need to send a notification
			return nil
		}
		cn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_UPDATED)
		select {
		case h.C <- cn:
		case <-h.stop:
		}
		return nil
	}
	// the name has changed; from a service consumer perspective, this is the
	// same as if the peer with the old name was removed and a new one added
	ocn := h.newChangeNotification(o, peerpb.ChangeNotificationType_PEER_DELETED)
	select {
	case h.C <- ocn:
	case <-h.stop:
		return nil
	}
	ncn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_ADDED)
	select {
	case h.C <- ncn:
	case <-h.stop:
	}
	return nil
}

// NodeDelete implements datapath.NodeHandler.NodeDelete.
func (h *handler) NodeDelete(n types.Node) error {
	cn := h.newChangeNotification(n, peerpb.ChangeNotificationType_PEER_DELETED)
	select {
	case h.C <- cn:
	case <-h.stop:
	}
	return nil
}

// NodeValidateImplementation implements
// datapath.NodeHandler.NodeValidateImplementation. It is a no-op.
func (h handler) NodeValidateImplementation(_ types.Node) error {
	// no-op
	return nil
}

// NodeConfigurationChanged implements
// datapath.NodeHandler.NodeValidateImplementation. It is a no-op.
func (h handler) NodeConfigurationChanged(_ datapath.LocalNodeConfiguration) error {
	// no-op
	return nil
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
	return &peerpb.ChangeNotification{
		Name:    n.Fullname(),
		Address: nodeAddress(n, h.addressPref),
		Type:    t,
		Tls:     tls,
	}
}

// nodeAddress returns the node's address. If the node has both IPv4 and IPv6
// addresses, pref controls which address type is returned.
func nodeAddress(n types.Node, pref serviceoption.AddressFamilyPreference) string {
	for _, family := range pref {
		switch family {
		case serviceoption.AddressFamilyIPv4:
			if addr := n.GetNodeIP(false); addr.To4() != nil {
				return addr.String()
			}
		case serviceoption.AddressFamilyIPv6:
			if addr := n.GetNodeIP(true); addr.To4() == nil {
				return addr.String()
			}
		}
	}
	return ""
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
