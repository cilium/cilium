// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

// SkipCRDCreation specifies whether the CustomResourceDefinition will be
// created by the daemon
const SkipCRDCreation = "skip-crd-creation"

// RegisterCRDsCell is a cell that creates all the Cilium CRDs.
var RegisterCRDsCell = cell.Module(
	"create-crds",
	"Create Cilium CRDs",

	cell.Config(defaultConfig),

	cell.Invoke(createCRDs),
)

type RegisterCRDsConfig struct {
	// SkipCRDCreation disables creation of the CustomResourceDefinition
	// for the operator
	SkipCRDCreation bool
}

var defaultConfig = RegisterCRDsConfig{}

func (c RegisterCRDsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions will not be created")
}

type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	Clientset k8sClient.Clientset

	Config RegisterCRDsConfig
}

func createCRDs(p params) {
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			// Register the CRDs after validating that we are running on a supported
			// version of K8s.
			if !p.Clientset.IsEnabled() || p.Config.SkipCRDCreation {
				p.Logger.Info("Skipping creation of CRDs")
				return nil
			}

			if err := RegisterCRDs(p.Clientset); err != nil {
				return fmt.Errorf("unable to create CRDs: %w", err)
			}
			return nil
		},
		OnStop: func(_ hive.HookContext) error {
			return nil
		},
	})
}
