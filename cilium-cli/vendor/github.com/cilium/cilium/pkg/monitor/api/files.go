// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import "fmt"

// Keep in sync with __source_file_name_to_id in bpf/source_names_to_ids.h.
var files = map[uint8]string{
	// @@ source files list begin

	// source files from bpf/
	1: "bpf_host.c",
	2: "bpf_lxc.c",
	3: "bpf_overlay.c",
	4: "bpf_xdp.c",
	5: "bpf_sock.c",
	6: "bpf_network.c",

	// header files from bpf/lib/
	101: "arp.h",
	102: "drop.h",
	103: "srv6.h",
	104: "icmp6.h",
	105: "nodeport.h",
	106: "lb.h",
	107: "mcast.h",
	108: "ipv4.h",
	109: "conntrack.h",
	110: "l3.h",
	111: "trace.h",
	112: "encap.h",
	113: "encrypt.h",

	// @@ source files list end
}

// BPFFileName returns the file name for the given BPF file id.
func BPFFileName(id uint8) string {
	if name, ok := files[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", id)
}
