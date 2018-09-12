// Copyright 2016-2018 Authors of Cilium
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

package ctmap

import (
	"fmt"
)

const (
	// MapTypeIPv4TCPLocal and friends are MapTypes which correspond to a
	// combination of the following attributes:
	// * IPv4 or IPv6;
	// * TCP or non-TCP (shortened to Any)
	// * Local (endpoint-specific) or global (endpoint-oblivious).
	MapTypeIPv4TCPLocal = iota
	MapTypeIPv6TCPLocal
	MapTypeIPv4TCPGlobal
	MapTypeIPv6TCPGlobal
	MapTypeIPv4AnyLocal
	MapTypeIPv6AnyLocal
	MapTypeIPv4AnyGlobal
	MapTypeIPv6AnyGlobal
	MapTypeMax
)

// MapType is a type of connection tracking map.
type MapType int

// String renders the map type into a user-readable string.
func (m MapType) String() string {
	switch m {
	case MapTypeIPv4TCPLocal:
		return "Local IPv4 TCP CT map"
	case MapTypeIPv6TCPLocal:
		return "Local IPv6 TCP CT map"
	case MapTypeIPv4TCPGlobal:
		return "Global IPv4 TCP CT map"
	case MapTypeIPv6TCPGlobal:
		return "Global IPv6 TCP CT map"
	case MapTypeIPv4AnyLocal:
		return "Local IPv4 non-TCP CT map"
	case MapTypeIPv6AnyLocal:
		return "Local IPv6 non-TCP CT map"
	case MapTypeIPv4AnyGlobal:
		return "Global IPv4 non-TCP CT map"
	case MapTypeIPv6AnyGlobal:
		return "Global IPv6 non-TCP CT map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

func (m MapType) isIPv4() bool {
	switch m {
	case MapTypeIPv4TCPLocal, MapTypeIPv4TCPGlobal, MapTypeIPv4AnyLocal, MapTypeIPv4AnyGlobal:
		return true
	}
	return false
}

func (m MapType) isIPv6() bool {
	switch m {
	case MapTypeIPv6TCPLocal, MapTypeIPv6TCPGlobal, MapTypeIPv6AnyLocal, MapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m MapType) isLocal() bool {
	switch m {
	case MapTypeIPv4TCPLocal, MapTypeIPv6TCPLocal, MapTypeIPv4AnyLocal, MapTypeIPv6AnyLocal:
		return true
	}
	return false
}

func (m MapType) isGlobal() bool {
	switch m {
	case MapTypeIPv4TCPGlobal, MapTypeIPv6TCPGlobal, MapTypeIPv4AnyGlobal, MapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m MapType) isTCP() bool {
	switch m {
	case MapTypeIPv4TCPLocal, MapTypeIPv6TCPLocal, MapTypeIPv4TCPGlobal, MapTypeIPv6TCPGlobal:
		return true
	}
	return false
}
