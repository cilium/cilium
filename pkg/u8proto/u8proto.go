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

var protoNames = map[int]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

var protoIDs = map[string]U8proto{
	"icmp":   1,
	"tcp":    6,
	"udp":    17,
	"icmpv6": 58,
}

type U8proto uint8

func (p *U8proto) String() string {
	proto := int(*p)

	if _, ok := protoNames[proto]; ok {
		return protoNames[proto]
	}
	return strconv.Itoa(proto)
}

func ParseProtocol(proto string) (U8proto, error) {
	if u, ok := protoIDs[strings.ToLower(proto)]; ok {
		return u, nil
	}
	return 0, fmt.Errorf("unknown protocol '%s'", proto)
}
