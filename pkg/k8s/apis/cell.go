// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package apis

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	bgpConfig "github.com/cilium/cilium/pkg/bgp/config"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
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

	cell.ProvidePrivate(
		newCiliumGroupCRDs,
	),
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

// RegisterCRDsFunc is a function that register all the CRDs for a k8s group
type RegisterCRDsFunc func(ctx context.Context, log *slog.Logger, clientset k8sClient.Clientset) (needsMigration []*apiextensionsv1.CustomResourceDefinition, err error)

type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JG        job.Group

	Clientset k8sClient.Clientset

	Config            RegisterCRDsConfig
	RegisterCRDsFuncs []RegisterCRDsFunc `group:"register-crd-funcs"`
}

func createCRDs(p params) {
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// Register the CRDs after validating that we are running on a supported
			// version of K8s.
			if !p.Clientset.IsEnabled() || p.Config.SkipCRDCreation {
				p.Logger.Info("Skipping creation of CRDs")
				return nil
			}

			// gather CRDs that need storage version migration
			migrateCRDs := []*apiextensionsv1.CustomResourceDefinition{}

			for _, f := range p.RegisterCRDsFuncs {
				if f == nil {
					continue
				}
				m, err := f(ctx, p.Logger, p.Clientset)
				if err != nil {
					return fmt.Errorf("unable to create CRDs: %w", err)
				}
				migrateCRDs = append(migrateCRDs, m...)
			}

			// If migration was requested, then schedule a separate job
			// for each requested CRD.
			for _, crd := range migrateCRDs {
				if crd == nil {
					continue
				}
				jobname := "crd-migrate-" + crd.Spec.Names.Plural
				log := p.Logger.WithGroup(jobname)
				p.JG.Add(job.OneShot(
					jobname,
					func(ctx context.Context, _ cell.Health) error {
						return crdhelpers.MigrateStorageVersion(ctx, log, p.Clientset, crd.Name)
					},
				))
			}
			return nil
		},
	})
}

type RegisterCRDsFuncOut struct {
	cell.Out

	Func RegisterCRDsFunc `group:"register-crd-funcs"`
}

func newCiliumGroupCRDs(bc bgpConfig.BGPConfig) RegisterCRDsFuncOut {
	return RegisterCRDsFuncOut{
		Func: func(ctx context.Context, l *slog.Logger, c k8sClient.Clientset) ([]*apiextensionsv1.CustomResourceDefinition, error) {
			return client.CreateCustomResourceDefinitions(ctx, l, c, bc)
		},
	}
}
