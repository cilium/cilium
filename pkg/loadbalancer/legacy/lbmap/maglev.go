// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
)

const (
	// Both outer maps are pinned though given we need to insert
	// inner maps into them.
	MaglevOuter4MapName = maps.MaglevOuter4MapName
	MaglevOuter6MapName = maps.MaglevOuter6MapName
)
