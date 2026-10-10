// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/cilium/cilium/pkg/k8s/apis"
	ciliumClient "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

type lrpOperatorConfig struct {
	EnableConfig `mapstructure:",squash"`
}

func (def lrpOperatorConfig) Flags(flags *pflag.FlagSet) {
	def.EnableConfig.Flags(flags)
	flags.MarkHidden(EnableLocalRedirectPolicyName)
}

var defaultLRPOperatorConfig = lrpOperatorConfig{EnableConfig: defaultEnableConfig}

// OperatorCell registers the CiliumLocalRedirectPolicy CRD when Local Redirect
// Policy support is enabled.
var OperatorCell = cell.Module(
	"local-redirect-policy-operator",
	"Local Redirect Policy operator support",

	cell.Config(defaultLRPOperatorConfig),
	cell.Provide(newLRPCRDRegistration),
)

func newLRPCRDRegistration(cfg lrpOperatorConfig) apis.RegisterCRDsFuncOut {
	return apis.RegisterCRDsFuncOut{
		Func: func(ctx context.Context, logger *slog.Logger, client k8sClient.Clientset) ([]*apiextensionsv1.CustomResourceDefinition, error) {
			if !cfg.IsEnabled() {
				return nil, nil
			}
			return ciliumClient.CreateCustomResourceDefinition(
				ctx,
				logger,
				client,
				ciliumv2.CLRPName,
			)
		},
	}
}
