package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controlplane/apiserver"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/datapath/lb"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

var h *hive.Hive

func main() {
	cmd := &cobra.Command{
		Use: "lbtest",
		Run: run,
	}

	h = hive.New(
		/*client.Cell,
		k8s.SharedResourcesCell,
		servicemanager.K8sHandlerCell,
		redirectpolicies.Cell,
		envoy.Cell,
		*/

		fakeServiceHandlerCell,

		servicemanager.Cell,

		apiserver.Cell,
		servicemanager.APIHandlersCell,

		lb.Cell,

		fakeLBMapCell,
	)
	h.RegisterFlags(cmd.Flags())

	cmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	f, err := os.Create("/tmp/lbtest.dot")
	if err != nil {
		panic(err)
	}
	h.WriteDotGraph(f)
	f.Close()

	h.PrintObjects()

	if err := h.Run(); err != nil {
		log.Fatal(err)
	}
}

var fakeLBMapCell = cell.Module(
	"fake-lbmap",
	"Fake LBMap",
	cell.Provide(
		func() datapathTypes.LBMap { return mockmaps.NewLBMockMap() },
	),
)

var fakeServiceHandlerCell = cell.Invoke(
	func(lc hive.Lifecycle, s servicemanager.ServiceManager) {
		lc.Append(hive.Hook{
			OnStart: func(hive.HookContext) error {
				go fakeServiceHandler(s)
				return nil
			},
		})
	},
)

func fakeServiceHandler(s servicemanager.ServiceManager) {
	h := s.NewHandle("fake")
	name := loadbalancer.ServiceName{
		Scope:     loadbalancer.Scope("fake"),
		Name:      "foo",
		Namespace: "bar",
	}
	feAddr := loadbalancer.NewL3n4Addr(
		"tcp",
		cmtypes.MustParseAddrCluster("1.2.3.4"),
		1234,
		loadbalancer.ScopeExternal,
	)

	fe := &loadbalancer.Frontend{
		Address: *feAddr,
		Type:    loadbalancer.SVCTypeClusterIP,
		Name:    name,
	}

	h.UpsertFrontend(name, fe)

	beAddr := loadbalancer.NewL3n4Addr(
		"tcp",
		cmtypes.MustParseAddrCluster("2.3.4.5"),
		2345,
		loadbalancer.ScopeExternal,
	)
	be := &loadbalancer.Backend{
		FEPortName: "http",
		NodeName:   "quux",
		L3n4Addr:   *beAddr,
	}

	h.UpsertBackends(name, be)

	h.Synchronized()

}
