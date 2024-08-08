// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/option"
)

var (
	localNodeConfig = datapath.LocalNodeConfiguration{
		NodeIPv4:           templateIPv4[:],
		CiliumInternalIPv4: templateIPv4[:],
		AllocCIDRIPv4:      cidr.MustParseCIDR("10.147.0.0/16"),
		LoopbackIPv4:       templateIPv4[:],
		HostEndpointID:     1,
		EnableIPv4:         true,
	}
)

func setupCompilationDirectories(tb testing.TB) {
	option.Config.DryMode = true
	option.Config.BpfDir = bpfDir
	option.Config.StateDir = bpfDir
	testIncludes = []string{
		// Unit tests rely on using bpf/ep_config.h instead of
		// the real per endpoint config. Otherwise you get compilation
		// errors due to redefined macros and such. *sigh*
		fmt.Sprintf("-I%s", bpfDir),
		fmt.Sprintf("-I%s", filepath.Join(bpfDir, "include")),
	}

	oldElfMapPrefixes := elfMapPrefixes
	elfMapPrefixes = []string{
		fmt.Sprintf("test_%s", callsmap.MapName),
	}

	tb.Cleanup(func() {
		option.Config.DryMode = false
		option.Config.BpfDir = ""
		option.Config.StateDir = ""
		testIncludes = nil
		elfMapPrefixes = oldElfMapPrefixes
	})
}

func newTestLoader(tb testing.TB) *loader {
	setupCompilationDirectories(tb)

	l := newLoader(Params{
		Sysctl: sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
	})
	cw := configWriterForTest(tb)
	l.templateCache = newObjectCache(cw, tb.TempDir())
	return l
}
