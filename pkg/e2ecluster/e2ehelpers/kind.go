// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package e2ehelpers

import (
	"context"

	klog "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
)

// MaybeCreateTempKindCluster creates a new temporary kind cluster in case no kubeconfig file is
// specified on the command line.
func MaybeCreateTempKindCluster(testenv env.Environment, namePrefix string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if cfg.KubeconfigFile() == "" {
			name := envconf.RandomName(namePrefix, 16)
			klog.Infof("No kubeconfig specified, creating temporary kind cluster %s", name)
			var err error
			ctx, err = envfuncs.CreateKindCluster(name)(ctx, cfg)
			if err != nil {
				return ctx, err
			}
			// Automatically clean up the cluster when the test finishes
			testenv.Finish(deleteTempKindCluster(name))
			return ctx, nil
		}
		return ctx, nil
	}
}

// deleteTempKindCluster deletes a new temporary kind cluster previously created using
// MaybeCreateTempKindCluster.
func deleteTempKindCluster(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.Infof("Deleting temporary kind cluster %s", clusterName)
		var err error
		ctx, err = envfuncs.DestroyKindCluster(clusterName)(ctx, cfg)
		if err != nil {
			return ctx, err
		}
		return ctx, nil
	}
}
