// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qos

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/cilium/cilium/pkg/k8s/apis"
	ciliumClient "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/qos/config"
)

// Cell provides the operator side of the QoS API. It is kept apart from the
// agent's pkg/qos so that the operator does not pull in the agent's QoS
// controller and datapath wiring.
var Cell = cell.Module(
	"qos-operator",
	"Network Quality of Service Operator",

	cell.Config(config.DefaultConfig),

	// Register the QoS CRDs when QoS is enabled.
	cell.Provide(newQoSCRDRegistration),
)

func newQoSCRDRegistration(cfg config.Config) apis.RegisterCRDsFuncOut {
	return apis.RegisterCRDsFuncOut{
		Func: func(ctx context.Context, logger *slog.Logger, client k8sClient.Clientset) ([]*apiextensionsv1.CustomResourceDefinition, error) {
			if !cfg.EnableQoS {
				return nil, nil
			}

			var needsMigration []*apiextensionsv1.CustomResourceDefinition
			for _, name := range []string{v2alpha1.CQMName, v2alpha1.CQCName, v2alpha1.CQPName} {
				crds, err := ciliumClient.CreateCustomResourceDefinition(ctx, logger, client, name)
				if err != nil {
					return nil, err
				}
				needsMigration = append(needsMigration, crds...)
			}
			return needsMigration, nil
		},
	}
}
