// Copyright 2016-2017 Authors of Cilium
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

package id

import (
	"fmt"
	"strconv"
	"strings"
)

type PrefixType string

func (s PrefixType) String() string { return string(s) }

const (
	CiliumLocalIdPrefix  PrefixType = "cilium-local"
	CiliumGlobalIdPrefix            = "cilium-global"
	ContainerIdPrefix               = "container-id"
	DockerEndpointPrefix            = "docker-endpoint"
	ContainerNamePrefix             = "container-name"
	PodNamePrefix                   = "pod-name"

	// IPv4Prefix is the prefix used in Cilium IDs when the identifier is
	// the IPv4 address of the endpoint
	IPv4Prefix = "ipv4"
)

func NewCiliumID(id int64) string {
	return fmt.Sprintf("%s:%d", CiliumLocalIdPrefix, id)
}

func NewID(prefix PrefixType, id string) string {
	return string(prefix) + ":" + id
}

// SplitID splits ID into prefix and id. No validation is performed on prefix.
func SplitID(id string) (PrefixType, string) {
	if s := strings.SplitN(id, ":", 2); len(s) == 2 {
		return PrefixType(s[0]), s[1]
	}

	// default prefix
	return CiliumLocalIdPrefix, id
}

// ParseCiliumID parses id as cilium endpoint id and returns numeric portion.
func ParseCiliumID(id string) (int64, error) {
	prefix, id := SplitID(id)
	if prefix != CiliumLocalIdPrefix {
		return 0, fmt.Errorf("not a cilium identifier")
	}
	n, err := strconv.ParseInt(id, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric cilium id: %s", err)
	}
	return n, nil
}

// ValidateID parses specified id and returns normalized id as string.
func ValidateID(id string) (PrefixType, string, error) {
	prefix, id := SplitID(id)
	switch prefix {
	case CiliumLocalIdPrefix, CiliumGlobalIdPrefix, ContainerIdPrefix, DockerEndpointPrefix, ContainerNamePrefix:
	case PodNamePrefix, IPv4Prefix, IPv6Prefix:
	default:
		return "", "", fmt.Errorf("Unknown id prefix %s", prefix)
	}

	return prefix, id, nil
}
