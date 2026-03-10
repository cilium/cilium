// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netns

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/afero"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

var fbSysctl = "net.core.fb_tunnels_only_for_init_net"

// As a side effect of importing the netns testutils, try to set
// net.core.fb_tunnels_only_for_init_net to 2 to stop the kernel from creating
// fallback tunnel devices (tunl0, ip6tnl0 and friends) in newly created network
// namespaces when running with sufficient privileges.
//
// This provides a more predictable test environment without needing to clean up
// devices before a test, e.g. for testing reconcilers, or having to run some
// tests in a separate bubble, which leads to sprawling complexity.
func init() {
	s := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	p := strings.Split(fbSysctl, ".")

	orig, err := s.ReadInt(p)
	if errors.Is(err, os.ErrNotExist) {
		// Probably running on non-Linux, don't generate noise.
		return
	}
	if err != nil {
		panic(fmt.Sprintf("Reading initial fb_tunnels value: %v", err))
	}

	err = s.WriteInt(p, 2)
	if errors.Is(err, os.ErrPermission) {
		// Running without sufficient privileges.
		return
	}
	if err != nil {
		panic(fmt.Sprintf("Setting fb_tunnels: %v", err))
	}

	if orig != 2 {
		fmt.Println("Changed", fbSysctl, "from", orig, "to 2")
	}
}
