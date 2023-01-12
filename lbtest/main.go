package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controlplane/apiserver"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/datapath/lb"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/status"
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

		cell.Invoke(printStatusReports),

		statusServerCell,
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
		loadbalancer.Backend{FEPortName: "http", NodeName: "quux", L3n4Addr: *beAddr},
	)

	h.Synchronized()

}

func printStatusReports(p *status.Provider) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR1)

	go func() {
		for range signals {
			printStatusOnSIGUSR1(p)
		}
	}()

	go func() {
		for s := range p.Stream(context.TODO()) {
			fmt.Printf("%s status: %s: %s\n", s.ModuleID, s.Level, s.Message)
		}

	}()
}

func printStatusOnSIGUSR1(p *status.Provider) {
	fmt.Printf("--- status report ---\n")
	for _, s := range p.All() {
		fmt.Printf("%s: %s: %q (%.1fs ago)\n", s.ModuleID, s.Level, s.Message,
			time.Now().Sub(s.LastUpdated).Seconds())
	}
	fmt.Printf("---------------------\n")
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

var statusServerCell = cell.Invoke(registerStatusServer)

func registerStatusServer(p *status.Provider, lc hive.Lifecycle) {
	mux := http.NewServeMux()
	srv := http.Server{
		Addr:    ":8888",
		Handler: mux,
	}
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		all := p.All()
		byLevel := map[status.Level][]status.ModuleStatus{}
		for _, s := range all {
			byLevel[s.Level] = append(byLevel[s.Level], s)
		}
		if len(byLevel[status.LevelOK]) == len(all) {
			fmt.Fprintf(w, "ok: %d/%d modules healthy\n", len(all), len(all))
			return
		} else {
			fmt.Fprintf(w, "degraded: %d/%d modules down or degraded\n",
				len(byLevel[status.LevelDegraded])+len(byLevel[status.LevelDown]),
				len(all))
		}

		for _, s := range byLevel[status.LevelDegraded] {
			fmt.Fprintf(w, "\n=== %s is degraded ===\n", s.ModuleID)
			w.Write([]byte(s.Message + "\n"))
		}

		for _, s := range byLevel[status.LevelDown] {
			fmt.Fprintf(w, "\n=== %s is down ===\n", s.ModuleID)
			w.Write([]byte(s.Message + "\n"))
		}
	})
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			go srv.ListenAndServe()
			return nil
		},
		OnStop: func(hive.HookContext) error {
			return srv.Close()
		},
	})

}
