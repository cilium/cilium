// Copyright 2018-2019 Authors of Cilium
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

package api

import (
	"fmt"
)

var errors = map[uint8]string{
	0:   "Success",
	2:   "Invalid packet",
	130: "Invalid source mac",
	131: "Invalid destination mac",
	132: "Invalid source ip",
	133: "Policy denied (L3)",
	134: "Invalid packet",
	135: "CT: Truncated or invalid header",
	136: "CT: Missing TCP ACK flag",
	137: "CT: Unknown L4 protocol",
	138: "CT: Can't create entry from packet", // Unused
	139: "Unsupported L3 protocol",
	140: "Missed tail call",
	141: "Error writing to packet",
	142: "Unknown L4 protocol",
	143: "Unknown ICMPv4 code",
	144: "Unknown ICMPv4 type",
	145: "Unknown ICMPv6 code",
	146: "Unknown ICMPv6 type",
	147: "Error retrieving tunnel key",
	148: "Error retrieving tunnel options", // Unused
	149: "Invalid Geneve option",           // Unused
	150: "Unknown L3 target address",
	151: "Not a local target address",
	152: "No matching local container found",
	153: "Error while correcting L3 checksum",
	154: "Error while correcting L4 checksum",
	155: "CT: Map insertion failed",
	156: "Invalid IPv6 extension header",
	157: "IP fragmentation not supported",
	158: "Service backend not found",
	159: "Policy denied (L4)",
	160: "No tunnel/encapsulation endpoint (datapath BUG!)",
	161: "Failed to insert into proxymap", // Unused
	162: "Policy denied (CIDR)",
	163: "Unknown connection tracking state",
	164: "Local host is unreachable",
	165: "No configuration available to perform policy decision",
	166: "Unsupported L2 protocol",
	167: "No mapping for NAT masquerade",
	168: "Unsupported protocol for NAT masquerade",
}

// DropReason prints the drop reason in a human readable string
func DropReason(reason uint8) string {
	if err, ok := errors[reason]; ok {
		return err
	}
	return fmt.Sprintf("%d", reason)
}
