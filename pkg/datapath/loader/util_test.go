// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func setupLocalNodeStore(tb testing.TB) {
	node.SetTestLocalNodeStore()
	node.InitDefaultPrefix("")
	node.SetInternalIPv4Router(templateIPv4[:])
	node.SetIPv4Loopback(templateIPv4[:])
	tb.Cleanup(node.UnsetTestLocalNodeStore)
}

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

	tb.Cleanup(func() {
		option.Config.DryMode = false
		option.Config.BpfDir = ""
		option.Config.StateDir = ""
		testIncludes = nil
	})
}

func newTestLoader(tb testing.TB) *loader {
	setupCompilationDirectories(tb)
	l := NewLoaderForTest(tb)
	l.templateCache = newObjectCache(&config.HeaderfileWriter{}, nil, tb.TempDir())
	return l
}
