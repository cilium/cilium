// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/node"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	core_v1 "k8s.io/api/core/v1"
)

var Cell = cell.Module(
	"xds-client",
	"xDS client",

	cell.Config(defaultConfig),
	cell.Provide(NewXDSClient),
)

type Config struct {
	ServerAddr string `mapstructure:"xds-server-address"`

	Options
}

var defaultConfig = Config{
	ServerAddr: "",
	Options:    *Defaults,
}

func (conf Config) Flags(flags *pflag.FlagSet) {
	flags.String("xds-server-address", conf.ServerAddr, "Address of xDS server")
	flags.Bool("xds-use-sotw-protocol", conf.UseSOTW, "Use State Of The World, non-incremental version of xDS protocol")
}

type input struct {
	cell.In

	Config
	JobGroup       job.Group
	Log            *slog.Logger
	LocalNodeStore *node.LocalNodeStore
}

func NewXDSClient(in input) (BaseLayer, error) {
	if in.Config.ServerAddr == "" {
		// Disabled
		return nil, nil
	}
	localNode, err := in.LocalNodeStore.Get(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to get LocalNodeStore: %w", err)
	}
	zone := localNode.Labels[core_v1.LabelTopologyZone]
	locality := &corepb.Locality{
		Zone: zone,
	}
	node := &corepb.Node{
		Id:            localNode.Name,
		UserAgentName: "cilium-agent",
		Locality:      locality,
	}
	cl := NewClient(in.Log, node, &in.Config.Options)
	in.JobGroup.Add(job.OneShot("xds-client-run", func(ctx context.Context, _ cell.Health) error {
		conn, err := grpc.NewClient(in.Config.ServerAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		return cl.Run(ctx, conn)
	}))
	return cl, nil
}
