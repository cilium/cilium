// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controllerruntime

import (
	"context"
	"fmt"

	"github.com/bombsimon/logrusr/v4"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

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

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Health    cell.Health

	K8sClient client.Clientset
	Scheme    *runtime.Scheme
}

func newManager(params managerParams) (ctrlRuntime.Manager, error) {
	if !params.K8sClient.IsEnabled() {
		return nil, nil
	}

	// Register special comparison function for proto resource to support
	// internal comparison of types depending on type (e.g. CiliumEnvoyConfig).
	equality.Semantic.AddFunc(func(xdsResource1, xdsResource2 ciliumv2.XDSResource) bool {
		return proto.Equal(xdsResource1.Any, xdsResource2.Any)
	})

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

	params.JobGroup.Add(job.OneShot("manager", func(ctx context.Context, health cell.Health) error {
		return mgr.Start(ctx)
	}))

	return mgr, nil
}
