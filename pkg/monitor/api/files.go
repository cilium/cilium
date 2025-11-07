// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import "fmt"

// Keep in sync with __id_for_file in bpf/lib/source_info.h.
var files = map[uint8]string{
	// @@ source files list begin

	// source files from bpf/
	1: "bpf_host.c",
	2: "bpf_lxc.c",
	3: "bpf_overlay.c",
	4: "bpf_xdp.c",
	5: "bpf_sock.c",
	6: "bpf_network.c",
	7: "bpf_wireguard.c",

	// header files from bpf/lib/
	101: "drop.h",
	102: "srv6.h",
	103: "icmp6.h",
	104: "nodeport.h",
	105: "lb.h",
	106: "mcast.h",
	107: "ipv4.h",
	108: "conntrack.h",
	109: "local_delivery.h",
	110: "trace.h",
	111: "encap.h",
	112: "host_firewall.h",
	113: "nodeport_egress.h",
	114: "ipv6.h",
	115: "classifiers.h",

	// @@ source files list end
}

// BPFFileName returns the file name for the given BPF file id.
func BPFFileName(id uint8) string {
	if name, ok := files[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", id)
}
