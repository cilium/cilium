// Copyright 2020 Authors of Cilium
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

package peer

import (
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/node/types"

	peerpb "github.com/cilium/cilium/api/v1/peer"
)

// handler implements the datapath.NodeHandler interface so that it can be
// subscribed to a node manager and receives update about nodes being
// added/updated/deleted. Node update information is turned into
// peerpb.ChangeNotification and sent to the channel C. As this channel is
// unbuffered, clients must be ready to read from it before subscribing the
// handler to the node manager.
// Once not used anymore, Close must be called to free resources.
type handler struct {
	stop chan struct{}
	C    chan *peerpb.ChangeNotification
}

func newHandler() *handler {
	return &handler{
		stop: make(chan struct{}),
		C:    make(chan *peerpb.ChangeNotification),
	}
}

// Ensure that Service implements the NodeHandler interface so that it can be
// notified of nodes updates by the daemon's node manager.
var _ datapath.NodeHandler = (*handler)(nil)

// NodeAdd implements datapath.NodeHandler.NodeAdd.
func (h *handler) NodeAdd(n types.Node) error {
	select {
	case h.C <- &peerpb.ChangeNotification{
		Name:    n.Fullname(),
		Address: nodeAddress(n),
		Type:    peerpb.ChangeNotificationType_PEER_ADDED,
	}:
	case <-h.stop:
	}
	return nil
}

// NodeUpdate implements datapath.NodeHandler.NodeUpdate.
func (h *handler) NodeUpdate(o, n types.Node) error {
	oAddr, nAddr := nodeAddress(o), nodeAddress(n)
	if o.Fullname() == n.Fullname() {
		if oAddr == nAddr {
			// this corresponds to the same peer
			// => no need to send a notification
			return nil
		}
		select {
		case h.C <- &peerpb.ChangeNotification{
			Name:    n.Fullname(),
			Address: nAddr,
			Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
		}:
		case <-h.stop:
		}
		return nil
	}
	// the name has changed; from a service consumer perspective, this is the
	// same as if the peer with the old name was removed and a new one added
	select {
	case h.C <- &peerpb.ChangeNotification{
		Name:    o.Fullname(),
		Address: oAddr,
		Type:    peerpb.ChangeNotificationType_PEER_DELETED,
	}:
	case <-h.stop:
		return nil
	}
	select {
	case h.C <- &peerpb.ChangeNotification{
		Name:    n.Fullname(),
		Address: nAddr,
		Type:    peerpb.ChangeNotificationType_PEER_ADDED,
	}:
	case <-h.stop:
	}
	return nil
}

// NodeDelete implements datapath.NodeHandler.NodeDelete.
func (h *handler) NodeDelete(n types.Node) error {
	select {
	case h.C <- &peerpb.ChangeNotification{
		Name:    n.Fullname(),
		Address: nodeAddress(n),
		Type:    peerpb.ChangeNotificationType_PEER_DELETED,
	}:
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

// nodeAddress returns the node's address. If the node has both IPv4 and IPv6
// addresses, IPv4 takes priority.
func nodeAddress(n types.Node) string {
	addr := n.GetNodeIP(false)
	if addr.To4() != nil {
		return addr.String()
	}
	addr = n.GetNodeIP(true)
	if addr == nil {
		return ""
	}
	return addr.String()
}
