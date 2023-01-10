// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

// Available options for datapath mode.
const (
	// DatapathModeVeth specifies veth datapath mode (i.e. containers are
	// attached to a network via veth pairs).
	DatapathModeVeth = "veth"

	// DatapathModeLBOnly specifies lb-only datapath mode.
	DatapathModeLBOnly = "lb-only"
)
