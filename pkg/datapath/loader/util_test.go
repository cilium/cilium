// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
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
		fmt.Sprintf("test_%s", policymap.MapName),
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

func testLoaderContext() datapath.LoaderContext {
	return datapath.LoaderContext{
		NodeIPv4:     templateIPv4[:],
		NodeIPv6:     nil,
		InternalIPv4: templateIPv4[:],
		InternalIPv6: nil,
		RangeIPv4:    cidr.MustParseCIDR("10.147.0.0/16"),
		LoopbackIPv4: templateIPv4[:],
		Devices:      []*tables.Device{},
		DeviceNames:  []string{},
		NodeAddrs:    []tables.NodeAddress{},
	}
}

func newTestLoader(tb testing.TB, lctx datapath.LoaderContext) *loader {
	setupCompilationDirectories(tb)
	l := NewLoaderForTest(tb)
	l.templateCache = newObjectCache(&config.HeaderfileWriter{}, tb.TempDir())
	l.templateCache.Update(lctx, nil)
	return l
}
