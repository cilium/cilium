// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

const (
	// Both outer maps are pinned though given we need to insert
	// inner maps into them.
	MaglevOuter4MapName = "cilium_lb4_maglev"
	MaglevOuter6MapName = "cilium_lb6_maglev"
)
