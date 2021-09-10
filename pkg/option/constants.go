// Copyright 2016-2019 Authors of Cilium
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

package option

const (
	// TCP_FIN, ... from <linux/tcp.h> (host byte-order)
	TCP_FIN = uint16(0x0001)
	TCP_SYN = uint16(0x0002)
	TCP_RST = uint16(0x0004)
	TCP_PSH = uint16(0x0008)
	TCP_ACK = uint16(0x0010)
	TCP_URG = uint16(0x0020)
	TCP_ECE = uint16(0x0040)
	TCP_CWR = uint16(0x0080)
)

var (
	TCPFlags = map[string]uint16{
		"none": uint16(0x0000),
		"all":  uint16(0x00FF),
		"fin":  TCP_FIN,
		"syn":  TCP_SYN,
		"rst":  TCP_RST,
		"psh":  TCP_PSH,
		"ack":  TCP_ACK,
		"urg":  TCP_URG,
		"ece":  TCP_ECE,
		"cwr":  TCP_CWR,
	}
)

type BPFClockSource int

const (
	ClockSourceKtime BPFClockSource = iota
	ClockSourceJiffies
)

const HostExtensionMKE = 0x1bda7a
