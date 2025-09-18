// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"

	core_v1 "k8s.io/api/core/v1"
)

type Config struct {
	ServerAddr string `mapstructure:"xds-server-address"`
	UseSOTW    bool   `mapstructure:"xds-use-sotw-protocol"`
	NodeID     string `mapstructure:"xds-node-id"`
}

var defaultConfig = Config{
	ServerAddr: "",
	UseSOTW:    true,
	NodeID:     "",
}

type DialOptionsProvider interface {
	GRPCOptions(context.Context) ([]grpc.DialOption, error)
}

type NodeProvider interface {
	Node(nodeID, zone string) *corepb.Node
}

// Cell defines a new module for xDS client.
// Cell requires providing:
// * DialOptionsProvider for configuring Dial Options for gRPC connection.
// * NodeProvider for building xds Node
var Cell = cell.Module(
	"xds-client",
	"Client library handling xds DiscoveryRequests with gRPC transport protocol",

	cell.Provide(newConnectionOptions),
	cell.Provide(newXDSClient),
	cell.Invoke(runXDSClient),
	cell.Config(defaultConfig),
)

// Flags implements Flagger interface
func (conf Config) Flags(flags *pflag.FlagSet) {
	flags.String("xds-server-address", conf.ServerAddr, "Address of xDS server")
	flags.Bool("xds-use-sotw-protocol", conf.UseSOTW, "Use State Of The World, non-incremental version of xDS protocol")
	flags.String("xds-node-id", conf.NodeID, "NodeID for xDS client")
}

type input struct {
	cell.In

	Config              Config
	ConnectionConfig    ConnectionOptions
	JobGroup            job.Group
	GRPCOptionsProvider DialOptionsProvider
	NodeBuilder         NodeProvider
	Log                 *slog.Logger
	LocalNodeStore      *node.LocalNodeStore
}

func newConnectionOptions() ConnectionOptions {
	return Defaults
}

// newXDSClient creates and a new instance of xDS client. XDS Server Address is
// required to create the client.
func newXDSClient(in input) (Client, error) {
	in.Log.Info("Init XDS client", logfields.Address, in.Config.ServerAddr)
	if in.Config.ServerAddr == "" {
		// Disabled
		return nil, fmt.Errorf("xDS Server address was not provided")
	}
	return NewClient(in.Log, in.Config.UseSOTW, &in.ConnectionConfig), nil
}

// runXDSClient adds a one shot job to wait for other dependencies to be
// initialized to create gRPC connection and run the client. When all
// dependencies are initialized the client is started.
func runXDSClient(in input, cl Client) {
	in.JobGroup.Add(job.OneShot("xds-client-run", func(ctx context.Context, _ cell.Health) error {
		localNode, err := in.LocalNodeStore.Get(context.TODO())
		if err != nil {
			return fmt.Errorf("Failed to get LocalNodeStore: %w", err)
		}
		zone := localNode.Labels[core_v1.LabelTopologyZone]
		in.Log.Info("Get local node", logfields.Zone, zone)
		if zone == "" {
			return fmt.Errorf("zone is nil")
		}
		nodeID := localNode.Name
		if in.Config.NodeID != "" {
			nodeID = in.Config.NodeID
		}

		node := in.NodeBuilder.Node(nodeID, zone)
		gOps, err := in.GRPCOptionsProvider.GRPCOptions(ctx)
		if err != nil {
			return fmt.Errorf("Error providing Options for GRPC connection: %w", err)
		}
		conn, err := grpc.NewClient(in.Config.ServerAddr, gOps...)
		if err != nil {
			return fmt.Errorf("Failed to create grpc Client: %w", err)
		}
		defer conn.Close()
		in.Log.Info("Successfully run xDS client")
		return cl.Run(ctx, node, conn)
	},
		job.WithRetry(3, &job.ExponentialBackoff{Min: 1 * time.Second, Max: 5 * time.Minute}),
	))
}
