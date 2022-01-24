// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package monitor

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
)

// linkMonitor watches for links on the system so that ifindexes can be
// string-formatted with human-readable interface names rather than the
// integer values.
//
// Package-level variable just to avoid overhauling old code to introduce an
// overarching structure to help format the messages nicely.
var linkMonitor getters.LinkGetter

func Init(linkGetter getters.LinkGetter) {
	linkMonitor = linkGetter
}

func ifname(ifindex int) string {
	if name, ok := linkMonitor.GetIfNameCached(ifindex); ok {
		return name
	}

	return fmt.Sprintf("%d", ifindex)
}
