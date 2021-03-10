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

package u8proto

import (
	"fmt"
	"strconv"
	"strings"
)

// These definitions must contain and be compatible with the string
// values defined for pkg/pollicy/api/L4Proto

const (
	// ANY represents all protocols.
	ANY    U8proto = 0
	ICMP   U8proto = 1
	TCP    U8proto = 6
	UDP    U8proto = 17
	ICMPv6 U8proto = 58
)

var protoNames = map[U8proto]string{
	0:  "ANY",
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

var ProtoIDs = map[string]U8proto{
	"all":    0,
	"any":    0,
	"none":   0,
	"icmp":   1,
	"tcp":    6,
	"udp":    17,
	"icmpv6": 58,
}

type U8proto uint8

func (p U8proto) String() string {
	if _, ok := protoNames[p]; ok {
		return protoNames[p]
	}
	return strconv.Itoa(int(p))
}

func ParseProtocol(proto string) (U8proto, error) {
	if u, ok := ProtoIDs[strings.ToLower(proto)]; ok {
		return u, nil
	}
	return 0, fmt.Errorf("unknown protocol %q", proto)
}

func FromNumber(proto uint8) (U8proto, error) {
	_, ok := protoNames[U8proto(proto)]
	if !ok {
		return 0, fmt.Errorf("unknown protocol %d", proto)
	}
	return U8proto(proto), nil
}
