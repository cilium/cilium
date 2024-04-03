// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

const (
	// ReconcilerLogField is used as key for reconciler name in the log field.
	ReconcilerLogField = "reconciler"

	// BGPNodeConfigLogField is used as key for BGP node config resource
	BGPNodeConfigLogField = "bgp_node_config"

	// InstanceLogField is used as key for BGP instance.
	InstanceLogField = "instance"

	// LocalASNLogField is used as key for BGP instance AS number
	LocalASNLogField = "asn"

	// ListenPortLogField is used as key for local port of BGP instance
	ListenPortLogField = "listen_port"

	// RouterIDLogField is used as key for BGP instance router ID
	RouterIDLogField = "router_id"

	// PeerLogField is used as key for BGP peer in the log field.
	PeerLogField = "peer"
)
