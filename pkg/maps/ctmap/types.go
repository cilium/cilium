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
	// MapTypeIPv4Local and friends are MapTypes which correspond to a
	// combination of the following attributes:
	// * IPv4 or IPv6;
	// * Local (endpoint-specific) or global (endpoint-oblivious).
	MapTypeIPv4Local = iota
	MapTypeIPv6Local
	MapTypeIPv4Global
	MapTypeIPv6Global
	MapTypeMax
)

// MapType is a type of connection tracking map.
type MapType int

// String renders the map type into a user-readable string.
func (m MapType) String() string {
	switch m {
	case MapTypeIPv4Local:
		return "Local IPv4 CT map"
	case MapTypeIPv6Local:
		return "Local IPv6 CT map"
	case MapTypeIPv4Global:
		return "Global IPv4 CT map"
	case MapTypeIPv6Global:
		return "Global IPv6 CT map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

func (m MapType) isIPv4() bool {
	switch m {
	case MapTypeIPv4Local, MapTypeIPv4Global:
		return true
	}
	return false
}

func (m MapType) isIPv6() bool {
	switch m {
	case MapTypeIPv6Local, MapTypeIPv6Global:
		return true
	}
	return false
}

func (m MapType) isLocal() bool {
	switch m {
	case MapTypeIPv4Local, MapTypeIPv6Local:
		return true
	}
	return false
}

func (m MapType) isGlobal() bool {
	switch m {
	case MapTypeIPv4Global, MapTypeIPv6Global:
		return true
	}
	return false
}
