// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package monitor

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/link"
)

func ifname(ifindex int) string {
	if name, ok := link.GetIfNameCached(ifindex); ok {
		return name
	}

	return fmt.Sprintf("%d", ifindex)
}
