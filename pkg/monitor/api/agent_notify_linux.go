// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

// Methods in this file are only used on Linux paired with the MonitorEvent interface.

// Dump prints the message according to the verbosity level specified
func (n *AgentNotify) Dump(args *DumpArgs) {
	if args.Verbosity == JSON {
		n.DumpJSON()
	} else {
		n.DumpInfo()
	}
}
