// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"

	operatorOption "github.com/cilium/cilium/operator/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var DefaultConfig = Config{
	EnableZTunnel: false,
}

type Config struct {
	EnableZTunnel bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
}

// Cell manages the ztunnel DaemonSet, ensuring a ztunnel proxy runs on each
// node in the cluster when ztunnel encryption is enabled.
var Cell = cell.Module(
	"ztunnel",
	"ZTunnel DaemonSet Controller",

	cell.Config(DefaultConfig),
	cell.Invoke(newZTunnelController),
)

type controllerParams struct {
	cell.In

	Lifecycle      cell.Lifecycle
	Logger         *slog.Logger
	Clientset      k8sClient.Clientset
	Config         Config
	OperatorConfig *operatorOption.OperatorConfig
}

//go:embed ztunnel-daemonset.yaml
var ztunnelDaemonSetYAML []byte

// createDaemonSet parses the embedded YAML and returns a DaemonSet object
func createDaemonSet(namespace string) (*appsv1.DaemonSet, error) {
	var daemonSet appsv1.DaemonSet
	if err := yaml.Unmarshal(ztunnelDaemonSetYAML, &daemonSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ztunnel DaemonSet YAML: %w", err)
	}
	daemonSet.Namespace = namespace
	return &daemonSet, nil
}

func newZTunnelController(params controllerParams) error {
	params.Logger.Info("Creating ZTunnel DaemonSet controller")

	c := &controller{
		client:         params.Clientset,
		logger:         params.Logger,
		config:         params.Config,
		operatorConfig: params.OperatorConfig,
	}

	ctx, cancel := context.WithCancel(context.Background())

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			params.Logger.Info("Starting ztunnel DaemonSet controller")
			go func() {
				// must parse embedded yaml into a daemon set
				ds, err := createDaemonSet(params.OperatorConfig.CiliumK8sNamespace)
				if err != nil {
					params.Logger.Error("Failed to create ztunnel DaemonSet",
						logfields.Error, err)
					return
				}

				if err := c.run(ctx, ds); err != nil {
					params.Logger.Error("ZTunnel controller error",
						logfields.Error, err)
				}
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			params.Logger.Info("Stopping ztunnel DaemonSet controller")
			cancel()
			return nil
		},
	})

	return nil
}
