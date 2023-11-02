// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controllerruntime

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/bombsimon/logrusr/v4"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
)

// Cell integrates the components of the controller-runtime library into Hive.
// The Kubernetes controller-runtime Project is a set of go libraries for building Controllers.
// See https://github.com/kubernetes-sigs/controller-runtime for further information.
var Cell = cell.Module(
	"controller-runtime",
	"Manages the controller-runtime integration and its components",

	cell.Provide(newScheme),
	cell.Provide(newManager),
)

func newScheme() (*runtime.Scheme, error) {
	scheme := clientgoscheme.Scheme

	for gv, f := range map[fmt.Stringer]func(s *runtime.Scheme) error{
		ciliumv2.SchemeGroupVersion: ciliumv2.AddToScheme,
	} {
		if err := f(scheme); err != nil {
			return nil, fmt.Errorf("failed to add types from %s to scheme: %w", gv, err)
		}
	}

	return scheme, nil
}

type managerParams struct {
	cell.In

	Logger      logrus.FieldLogger
	Lifecycle   hive.Lifecycle
	JobRegistry job.Registry
	Scope       cell.Scope

	K8sClient client.Clientset
	Scheme    *runtime.Scheme
}

func newManager(params managerParams) (ctrlRuntime.Manager, error) {
	if !params.K8sClient.IsEnabled() {
		return nil, nil
	}

	ctrlRuntime.SetLogger(logrusr.New(params.Logger))

	mgr, err := ctrlRuntime.NewManager(params.K8sClient.RestConfig(), ctrlRuntime.Options{
		Scheme: params.Scheme,
		// Disable controller metrics server in favour of cilium's metrics server.
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		Logger: logrusr.New(params.Logger),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new controller-runtime manager: %w", err)
	}

	jobGroup := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "controller-runtime")),
	)

	jobGroup.Add(job.OneShot("manager", func(ctx context.Context, health cell.HealthReporter) error {
		return mgr.Start(ctx)
	}))

	params.Lifecycle.Append(jobGroup)

	return mgr, nil
}
