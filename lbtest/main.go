package main

import (
	"log"
	"os"

	"github.com/cilium/cilium/pkg/controlplane/apiserver"
	"github.com/cilium/cilium/pkg/controlplane/redirectpolicies"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/datapath/lb"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/spf13/cobra"
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

		servicemanager.Cell,

		apiserver.Cell,
		servicemanager.APIHandlersCell,

		redirectpolicies.Cell,

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
