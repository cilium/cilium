// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"

	"github.com/spf13/pflag"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var Cell = cell.Module(
	"datapath-plugins",
	"Datapath plugins",

	cell.Config(defaultDatapathPluginsConfig),
	cell.Provide(newDatapathPluginClient),
)

type datapathPluginsConfig struct {
	DatapathPluginsEnabled    bool
	DatapathPluginsUnixSocket string
}

func (c datapathPluginsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("datapath-plugins-enabled", c.DatapathPluginsEnabled, "Flag to enable datapath plugins.")
	flags.String("datapath-plugins-unix-socket", c.DatapathPluginsUnixSocket, "Path to a UNIX domain socket for talking to a Cilium datapath plugin.")
}

var defaultDatapathPluginsConfig = datapathPluginsConfig{}

type Client interface {
	datapathplugins.DatapathPluginClient
	io.Closer
}

type client struct {
	conn *grpc.ClientConn
	datapathplugins.DatapathPluginClient
}

func (c *client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func newDatapathPluginClient(logger *slog.Logger, config datapathPluginsConfig) (Client, error) {
	if !config.DatapathPluginsEnabled {
		logger.Info("Disabling datapath plugins.")

		return nil, nil
	}

	if !option.Config.EnableTCX {
		logger.Info("Disabling datapath plugins; TCX is not enabled")

		return nil, nil
	}

	logger.Info("Enabling datapath plugins", logfields.Path, config.DatapathPluginsUnixSocket)

	conn, err := grpc.NewClient("unix://"+config.DatapathPluginsUnixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return &client{conn, datapathplugins.NewDatapathPluginClient(conn)}, nil
}
