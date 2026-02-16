// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/spf13/afero"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

var (
	localNodeConfig = datapath.LocalNodeConfiguration{
		NodeIPv4:            templateIPv4[:],
		CiliumInternalIPv4:  netip.AddrFrom4([4]byte(templateIPv4)),
		AllocCIDRIPv4:       cidr.MustParseCIDR("10.147.0.0/16"),
		ServiceLoopbackIPv4: templateIPv4[:],
		ServiceLoopbackIPv6: templateIPv6[:],
		HostEndpointID:      1,
		EnableIPv4:          true,
	}
)

func setupCompilationDirectories(tb testing.TB) {
	option.Config.DryMode = true
	option.Config.BpfDir = bpfDir
	option.Config.StateDir = tb.TempDir()
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

	var l *loader
	err := hive.New(
		cell.Invoke(func(ld datapath.Loader) {
			l = ld.(*loader)
		}),
		Cell,

		routeReconciler.TableCell,
		cell.Provide(func() (_ statedbReconciler.Reconciler[*routeReconciler.DesiredRoute]) {
			return nil
		}),
		cell.Provide(tables.NewDeviceTable), cell.Provide(statedb.RWTable[*tables.Device].ToTable),
		cell.Provide(func() (
			sysctl.Sysctl,
			datapath.ConfigWriter,
			*manager.NodeConfigNotifier,
			promise.Promise[endpointstate.Restorer],
			datapath.PreFilter,
		) {
			resolver, promise := promise.New[endpointstate.Restorer]()
			resolver.Resolve(&FakeRestorer{})
			return sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
				configWriterForTest(tb),
				&manager.NodeConfigNotifier{},
				promise,
				&FakePreFilter{}
		}),
		cell.Provide(func() *bigtcp.Configuration {
			return &bigtcp.Configuration{}
		}),
	).Populate(hivetest.Logger(tb))
	if err != nil {
		tb.Fatal(err)
	}

	return l
}

type FakeRestorer struct{}

func (fr *FakeRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return nil
}

func (fr *FakeRestorer) WaitForEndpointRestore(ctx context.Context) error { return nil }

func (fr *FakeRestorer) WaitForInitialPolicy(ctx context.Context) error { return nil }

type FakePreFilter struct{}

func (fpf *FakePreFilter) Enabled() bool { return true }

func (fpf *FakePreFilter) WriteConfig(fw io.Writer) {}

func (fpf *FakePreFilter) Dump(to []string) ([]string, int64) { return nil, 0 }

func (fpf *FakePreFilter) Insert(revision int64, cidrs []net.IPNet) error { return nil }

func (fpf *FakePreFilter) Delete(revision int64, cidrs []net.IPNet) error { return nil }
