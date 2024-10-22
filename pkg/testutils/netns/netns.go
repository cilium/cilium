// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netns

import (
	"testing"

	"github.com/cilium/cilium/pkg/netns"
)

// NewNetNS returns a new network namespace.
func NewNetNS(tb testing.TB) *netns.NetNS {
	tb.Helper()

	ns, err := netns.New()
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		ns.Close()
	})

	return ns
}
