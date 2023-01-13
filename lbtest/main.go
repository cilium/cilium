package main

import (
	"context"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/controlplane/apiserver"
	"github.com/cilium/cilium/controlplane/servicemanager"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/lb"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
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
		client.Cell,
		k8s.SharedResourcesCell,
		servicemanager.K8sHandlerCell,
		/*redirectpolicies.Cell,*/
		envoy.EnvoyConfigHandlerCell,
		cell.Provide(fakeEnvoyCache),

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
		Authority: loadbalancer.Authority("fake"),
		Name:      "foo",
		Namespace: "bar",
	}
	feAddr := loadbalancer.NewL3n4Addr(
		"tcp",
		cmtypes.MustParseAddrCluster("1.2.3.4"),
		1234,
		loadbalancer.ScopeExternal,
	)

	fe := &loadbalancer.FEClusterIP{
		CommonFE: loadbalancer.CommonFE{
			Name: name,
		},
		L3n4Addr: *feAddr,
	}
	h.UpsertFrontend(fe)

	beAddr := loadbalancer.NewL3n4Addr(
		"tcp",
		cmtypes.MustParseAddrCluster("2.3.4.5"),
		2345,
		loadbalancer.ScopeExternal,
	)

	h.UpsertBackends(name,
		&loadbalancer.Backend{FEPortName: "http", NodeName: "quux", L3n4Addr: *beAddr},
	)

	h.Synchronized()

}

type fakeEC struct{}

// AckProxyPort implements envoy.EnvoyCache
func (*fakeEC) AckProxyPort(ctx context.Context, name string) error {
	panic("unimplemented")
}

// AllocateProxyPort implements envoy.EnvoyCache
func (*fakeEC) AllocateProxyPort(name string, ingress bool) (uint16, error) {
	panic("unimplemented")
}

// ReleaseProxyPort implements envoy.EnvoyCache
func (*fakeEC) ReleaseProxyPort(name string) error {
	panic("unimplemented")
}

// UpsertEnvoyEndpoints implements envoy.EnvoyCache
func (*fakeEC) UpsertEnvoyEndpoints(loadbalancer.ServiceName, map[string][]*loadbalancer.Backend) error {
	panic("unimplemented")
}

// UpsertEnvoyResources implements envoy.EnvoyCache
func (*fakeEC) UpsertEnvoyResources(context.Context, envoy.Resources) error {
	panic("unimplemented")
}

var _ envoy.EnvoyCache = &fakeEC{}

func fakeEnvoyCache() envoy.EnvoyCache {
	return &fakeEC{}
}
