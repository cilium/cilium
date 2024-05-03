// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package id

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// MaxEndpointID is the maximum endpoint identifier.
const MaxEndpointID = math.MaxUint16

// PrefixType describes the type of endpoint identifier
type PrefixType string

func (s PrefixType) String() string { return string(s) }

const (
	// CiliumLocalIdPrefix is a numeric identifier with local scope. It has
	// no cluster wide meaning and is only unique in the scope of a single
	// agent. An endpoint is guaranteed to always have a local scope identifier.
	CiliumLocalIdPrefix PrefixType = "cilium-local"

	// CiliumGlobalIdPrefix is an endpoint identifier with global scope.
	// This addressing mechanism is currently unused.
	CiliumGlobalIdPrefix PrefixType = "cilium-global"

	// ContainerIdPrefix is used to address an endpoint via its primary
	// container ID. The container ID is specific to the container runtime
	// in use. Only the primary container that defines the networking scope
	// can be used to address an endpoint.
	// This can only be used to look up endpoints which have not opted-out of
	// legacy identifiers.
	// Deprecated. Use CNIAttachmentIdPrefix instead
	ContainerIdPrefix PrefixType = "container-id"

	// CNIAttachmentIdPrefix is used to address an endpoint via its primary
	// container ID and container interface passed to the CNI plugin.
	// This attachment ID uniquely identifies a CNI ADD and CNI DEL invocation pair.
	CNIAttachmentIdPrefix PrefixType = "cni-attachment-id"

	// DockerEndpointPrefix is used to address an endpoint via the Docker
	// endpoint ID. This method is only possible if the endpoint was
	// created via the cilium-docker plugin and the container is backed by
	// the libnetwork abstraction.
	DockerEndpointPrefix PrefixType = "docker-endpoint"

	// ContainerNamePrefix is used to address the endpoint via the
	// container's name. This addressing mechanism depends on the container
	// runtime. Only the primary container that the networking scope can be
	// used to address an endpoint.
	// This can only be used to look up endpoints which have not opted-out of
	// legacy identifiers.
	// Deprecated. Use CNIAttachmentIdPrefix instead
	ContainerNamePrefix PrefixType = "container-name"

	// CEPNamePrefix is used to address an endpoint via its Kubernetes
	// CiliumEndpoint resource name. This addressing only works if the endpoint
	// is represented as a Kubernetes CiliumEndpoint resource.
	CEPNamePrefix PrefixType = "cep-name"

	// PodNamePrefix is used to address an endpoint via the Kubernetes pod
	// name. This addressing only works if the endpoint represents as
	// Kubernetes pod.
	// This can only be used to look up endpoints which have not opted-out of
	// legacy identifiers.
	// Deprecated. May not be unique. Use CEPNamePrefix instead.
	PodNamePrefix PrefixType = "pod-name"

	// IPv4Prefix is used to address an endpoint via the endpoint's IPv4
	// address.
	IPv4Prefix PrefixType = "ipv4"

	// IPv6Prefix is the prefix used to refer to an endpoint via IPv6 address
	IPv6Prefix PrefixType = "ipv6"
)

// NewCiliumID returns a new endpoint identifier of type CiliumLocalIdPrefix
func NewCiliumID(id int64) string {
	return NewID(CiliumLocalIdPrefix, strconv.FormatInt(id, 10))
}

// NewID returns a new endpoint identifier
func NewID(prefix PrefixType, id string) string {
	return string(prefix) + ":" + id
}

// NewIPPrefixID returns an identifier based on the IP address specified. If ip
// is invalid, an empty string is returned.
func NewIPPrefixID(ip netip.Addr) string {
	if ip.IsValid() {
		if ip.Is4() {
			return NewID(IPv4Prefix, ip.String())
		}
		return NewID(IPv6Prefix, ip.String())
	}
	return ""
}

// NewCNIAttachmentID returns an identifier based on the CNI attachment ID. If
// the containerIfName is empty, only the containerID will be used.
func NewCNIAttachmentID(containerID, containerIfName string) string {
	id := containerID
	if containerIfName != "" {
		id = containerID + ":" + containerIfName
	}
	return NewID(CNIAttachmentIdPrefix, id)
}

// splitID splits ID into prefix and id. No validation is performed on prefix.
func splitID(id string) (PrefixType, string) {
	if idx := strings.IndexByte(id, ':'); idx > -1 {
		return PrefixType(id[:idx]), id[idx+1:]
	}

	// default prefix
	return CiliumLocalIdPrefix, id
}

// ParseCiliumID parses id as cilium endpoint id and returns numeric portion.
func ParseCiliumID(id string) (int64, error) {
	prefix, id := splitID(id)
	if prefix != CiliumLocalIdPrefix {
		return 0, fmt.Errorf("not a cilium identifier")
	}
	n, err := strconv.ParseInt(id, 0, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid numeric cilium id: %w", err)
	}
	if n > MaxEndpointID {
		return 0, fmt.Errorf("endpoint id too large: %d", n)
	}
	return n, nil
}

// Parse parses a string as an endpoint identified consists of an optional
// prefix [prefix:] followed by the identifier.
func Parse(id string) (PrefixType, string, error) {
	prefix, id := splitID(id)
	switch prefix {
	case CiliumLocalIdPrefix,
		CiliumGlobalIdPrefix,
		CNIAttachmentIdPrefix,
		ContainerIdPrefix,
		DockerEndpointPrefix,
		ContainerNamePrefix,
		CEPNamePrefix,
		PodNamePrefix,
		IPv4Prefix,
		IPv6Prefix:
		return prefix, id, nil
	}

	return "", "", fmt.Errorf("unknown endpoint ID prefix \"%s\"", prefix)
}
