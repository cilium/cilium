// Copyright 2018-2021 Authors of Cilium
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

// DropMin numbers less than this are non-drop reason codes
var DropMin uint8 = 130

// DropInvalid is the Invalid packet reason.
var DropInvalid uint8 = 2

// These values are shared with bpf/lib/common.h and api/v1/flow/flow.proto.
var errors = map[uint8]string{
	0:   "Success",
	2:   "Invalid packet",
	3:   "Interface",
	4:   "Interface Decrypted",
	5:   "LB, sock cgroup: No backend slot entry found",
	6:   "LB, sock cgroup: No backend entry found",
	7:   "LB, sock cgroup: Reverse entry update failed",
	8:   "LB, sock cgroup: Reverse entry stale",
	9:   "Fragmented packet",
	10:  "Fragmented packet entry update failed",
	11:  "Missed tail call to custom program",
	130: "Invalid source mac",      // Unused
	131: "Invalid destination mac", // Unused
	132: "Invalid source ip",
	133: "Policy denied",
	134: "Invalid packet",
	135: "CT: Truncated or invalid header",
	136: "Fragmentation needed",
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
	151: "Stale or unroutable IP",
	152: "No matching local container found", // Unused
	153: "Error while correcting L3 checksum",
	154: "Error while correcting L4 checksum",
	155: "CT: Map insertion failed",
	156: "Invalid IPv6 extension header",
	157: "IP fragmentation not supported",
	158: "Service backend not found",
	160: "No tunnel/encapsulation endpoint (datapath BUG!)",
	161: "Failed to insert into proxymap", // Unused
	162: "Reached EDT rate-limiting drop horizon",
	163: "Unknown connection tracking state",
	164: "Local host is unreachable",
	165: "No configuration available to perform policy decision", // Unused
	166: "Unsupported L2 protocol",
	167: "No mapping for NAT masquerade",
	168: "Unsupported protocol for NAT masquerade",
	169: "FIB lookup failed",
	170: "Encapsulation traffic is prohibited",
	171: "Invalid identity",
	172: "Unknown sender",
	173: "NAT not needed",
	174: "Is a ClusterIP",
	175: "First logical datagram fragment not found",
	176: "Forbidden ICMPv6 message",
	177: "Denied by LB src range check",
	178: "Socket lookup failed",
	179: "Socket assign failed",
	180: "Proxy redirection not supported for protocol",
	181: "Policy denied by denylist",
}

// DropReason prints the drop reason in a human readable string
func DropReason(reason uint8) string {
	if err, ok := errors[reason]; ok {
		return err
	}
	return fmt.Sprintf("%d", reason)
}
