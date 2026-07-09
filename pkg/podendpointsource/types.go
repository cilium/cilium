// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podendpointsource

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/labels"
)

// EventKind describes the kind of change an Event carries.
type EventKind int

const (
	// EventKindUpsert signals that a pod endpoint was added or updated.
	//
	// Consumers may replace any cached copy keyed by Endpoint.Key.
	EventKindUpsert EventKind = iota

	// EventKindDelete signals that a pod endpoint was removed.
	//
	// The PodEndpoint field identifies the deleted endpoint by Key; its
	// other fields are best-effort and MUST NOT be relied upon.
	EventKindDelete
)

// PodEndpoint is a snapshot of a pod endpoint assembled from IPCache state.
//
// A PodEndpoint is uniquely identified by Key (namespace/podName). Consumers
// should treat all fields as immutable.
type PodEndpoint struct {
	// Key is "namespace/podName".
	Key string

	// IPs are sorted by netip.Addr.Compare.
	IPs []netip.Addr

	// Labels are the endpoint's identity labels.
	// Nil iff the labels could not be resolved.
	Labels labels.LabelArray

	// NodeIP is the IP of the node the endpoint runs on. May be empty if
	// the IPCache entry did not carry a host IP.
	NodeIP string
}

// Event is emitted by a Source whenever a pod endpoint changes.
type Event struct {
	Kind     EventKind
	Endpoint PodEndpoint
}
