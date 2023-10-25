// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"

	"github.com/bombsimon/logrusr/v4"
	"github.com/spf13/pflag"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
)

// Cell manages the Gateway API related controllers.
var Cell = cell.Module(
	"gateway-api",
	"Manages the Gateway API controllers",

	cell.Config(gatewayApiConfig{
		EnableGatewayAPISecretsSync: true,
		GatewayAPISecretsNamespace:  "cilium-secrets",
	}),
	cell.Invoke(registerController),
)

type gatewayApiConfig struct {
	EnableGatewayAPISecretsSync bool
	GatewayAPISecretsNamespace  string
}

func (r gatewayApiConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-gateway-api-secrets-sync", r.EnableGatewayAPISecretsSync, "Enables fan-in TLS secrets sync from multiple namespaces to singular namespace (specified by gateway-api-secrets-namespace flag)")
	flags.String("gateway-api-secrets-namespace", r.GatewayAPISecretsNamespace, "Namespace having tls secrets used by CEC for Gateway API")
}

func registerController(lc hive.Lifecycle, config gatewayApiConfig) error {
	if !operatorOption.Config.EnableGatewayAPI {
		return nil
	}

	// Setting global logger for controller-runtime
	ctrlRuntime.SetLogger(logrusr.New(logging.DefaultLogger, logrusr.WithName("controller-runtime")))

	gatewayController, err := NewController(
		config.EnableGatewayAPISecretsSync,
		config.GatewayAPISecretsNamespace,
		operatorOption.Config.ProxyIdleTimeoutSeconds,
	)
	if err != nil {
		return fmt.Errorf("failed to create gateway controller: %w", err)
	}

	lc.Append(hive.Hook{
		OnStart: func(_ hive.HookContext) error {
			go gatewayController.Run()
			return nil
		},
	})

	return nil
}
