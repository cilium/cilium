// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package id

import (
	"fmt"
	"math"
	"net"
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
	ContainerIdPrefix PrefixType = "container-id"

	// DockerEndpointPrefix is used to address an endpoint via the Docker
	// endpoint ID. This method is only possible if the endpoint was
	// created via the cilium-docker plugin and the container is backed by
	// the libnetwork abstraction.
	DockerEndpointPrefix PrefixType = "docker-endpoint"

	// ContainerNamePrefix is used to address the endpoint via the
	// container's name. This addressing mechanism depends on the container
	// runtime. Only the primary container that the networking scope can be
	// used to address an endpoint.
	ContainerNamePrefix PrefixType = "container-name"

	// PodNamePrefix is used to address an endpoint via the Kubernetes pod
	// name. This addressing only works if the endpoint represents as
	// Kubernetes pod.
	PodNamePrefix PrefixType = "pod-name"

	// IPv4Prefix is used to address an endpoint via the endpoint's IPv4
	// address.
	IPv4Prefix PrefixType = "ipv4"

	// IPv6Prefix is the prefix used to refer to an endpoint via IPv6 address
	IPv6Prefix PrefixType = "ipv6"
)

// NewCiliumID returns a new endpoint identifier of type CiliumLocalIdPrefix
func NewCiliumID(id int64) string {
	return fmt.Sprintf("%s:%d", CiliumLocalIdPrefix, id)
}

// NewID returns a new endpoint identifier
func NewID(prefix PrefixType, id string) string {
	return string(prefix) + ":" + id
}

// NewIPPrefixID returns an identifier based on the IP address specified
func NewIPPrefixID(ip net.IP) string {
	if ip.To4() != nil {
		return NewID(IPv4Prefix, ip.String())
	}

	return NewID(IPv6Prefix, ip.String())
}

// splitID splits ID into prefix and id. No validation is performed on prefix.
func splitID(id string) (PrefixType, string) {
	if idx := strings.Index(id, ":"); idx > -1 {
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
		return 0, fmt.Errorf("invalid numeric cilium id: %s", err)
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
	case CiliumLocalIdPrefix, CiliumGlobalIdPrefix, ContainerIdPrefix, DockerEndpointPrefix, ContainerNamePrefix, PodNamePrefix, IPv4Prefix, IPv6Prefix:
		return prefix, id, nil
	}

	return "", "", fmt.Errorf("unknown endpoint ID prefix \"%s\"", prefix)
}
