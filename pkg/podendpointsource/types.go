// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podendpointsource

import (
	"net/netip"
)

// EventKind describes the kind of change an Event carries.
type EventKind int

const (
	// EventKindUpsert signals that a pod endpoint was added or updated.
	//
	// The event's PodEndpoint reflects the endpoint's current state after
	// applying the change. Consumers may safely replace any cached copy
	// keyed by Endpoint.ID with the endpoint carried by the event.
	EventKindUpsert EventKind = iota

	// EventKindDelete signals that a pod endpoint was removed.
	//
	// The PodEndpoint field identifies the deleted endpoint by ID; its
	// IPs, Labels and NodeIP fields are best-effort and MUST NOT be relied
	// upon. Consumers should drop any cached copy keyed by Endpoint.ID.
	EventKindDelete
)

// PodEndpoint is a snapshot of a pod endpoint assembled from IPCache state.
//
// A PodEndpoint is uniquely identified by ID (namespace/podName) and groups
// all pod IPs (IPv4 and IPv6) belonging to that pod along with its identity
// labels and the IP of the node it runs on. IPs are sorted with IPv4
// addresses first, followed by IPv6 addresses, each family ordered by its
// numeric address. This matches the ordering that downstream consumers of
// CiliumEndpoint-based sources have historically observed.
type PodEndpoint struct {
	// ID is "namespace/podName".
	ID string

	// IPs are the endpoint's pod IPs. Sorted IPv4-first then IPv6, numeric
	// within each family.
	IPs []netip.Addr

	// Labels are the endpoint's identity labels in the k8s string-map form.
	// Nil iff the labels could not be resolved.
	Labels map[string]string

	// NodeIP is the IP of the node the endpoint runs on. May be empty if
	// the IPCache entry did not carry a host IP.
	NodeIP string
}

// Event is emitted by a Source whenever a pod endpoint changes.
type Event struct {
	Kind     EventKind
	Endpoint PodEndpoint
}
