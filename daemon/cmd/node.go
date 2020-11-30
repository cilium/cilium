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

package cmd

import (
	"net"

	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/go-openapi/runtime/middleware"
)

func NewPutClusterNodesNeighHandler(d *Daemon) PutClusterNodesNeighHandler {
	return &nodeNeighInserter{
		d: d,
	}
}

func NewDeleteClusterNodesNeighHandler(d *Daemon) DeleteClusterNodesNeighHandler {
	return &nodeNeighRemover{
		d: d,
	}
}

type nodeNeighInserter struct {
	lock.Mutex

	d *Daemon
}

func (h *nodeNeighInserter) Handle(params PutClusterNodesNeighParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /cluster/nodes/neigh request")

	h.Lock()
	defer h.Unlock()

	node := nodeTypes.Node{
		Name:        params.Request.Name,
		IPAddresses: make([]nodeTypes.Address, 0, 1),
	}

	ip := net.ParseIP(params.Request.IP)

	if ip4 := ip.To4(); ip4 != nil {
		node.IPAddresses = append(node.IPAddresses, nodeTypes.Address{
			// We assume it will always be an internal IP because node
			// neighbors are reachable either through the L2 network or a next
			// hop (L3).
			Type: addressing.NodeInternalIP,
			IP:   ip4,
		})
	} else if ip6 := ip.To16(); ip6 != nil {
		// IPv6 is not supported.
		return NewPutClusterNodesNeighInvalid()
	} else {
		return NewPutClusterNodesNeighFailure()
	}

	if err := h.d.Datapath().Node().NodeNeighInsert(node); err != nil {
		log.WithError(err).Error("Failed to insert node as a neighbor")
		return NewPutClusterNodesNeighFailure()
	}

	return NewPutClusterNodesNeighCreated()
}

type nodeNeighRemover nodeNeighInserter

func (h *nodeNeighRemover) Handle(params DeleteClusterNodesNeighParams) middleware.Responder {
	log.WithField(
		logfields.Params, logfields.Repr(params),
	).Debug("DELETE /cluster/nodes/neigh request")

	h.Lock()
	defer h.Unlock()

	node := nodeTypes.Node{
		Name:        params.Request.Name,
		IPAddresses: make([]nodeTypes.Address, 0, 1),
	}

	ip := net.ParseIP(params.Request.IP)

	if ip4 := ip.To4(); ip4 != nil {
		node.IPAddresses = append(node.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   ip4,
		})
	} else if ip6 := ip.To16(); ip6 != nil {
		// IPv6 is not supported.
		return NewDeleteClusterNodesNeighInvalid()
	} else {
		return NewDeleteClusterNodesNeighFailure()
	}

	if err := h.d.Datapath().Node().NodeNeighRemove(node); err != nil {
		log.WithError(err).Error("Failed to remove neighbor node")
		return NewDeleteClusterNodesNeighFailure()
	}

	return NewDeleteClusterNodesNeighOK()
}
