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

const keyTempClusterName = "tempClusterName"

type helperContextKey string

// MaybeCreateTempKindCluster creates a new temporary kind cluster in case no kubeconfig file is
// specified on the command line.
func MaybeCreateTempKindCluster(namePrefix string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if cfg.KubeconfigFile() == "" {
			name := envconf.RandomName(namePrefix, 16)
			klog.Infof("No kubeconfig specified, creating temporary kind cluster %s", name)
			var err error
			ctx, err = envfuncs.CreateKindCluster(name)(ctx, cfg)
			if err != nil {
				return ctx, err
			}
			return context.WithValue(ctx, helperContextKey(keyTempClusterName), name), nil
		}
		return ctx, nil
	}
}

// MaybeDeleteTempKindCluster deletes a new temporary kind cluster previously createed using
// MaybeDeleteTempKindCluster.
func MaybeDeleteTempKindCluster() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		tempClusterName := ctx.Value(helperContextKey(keyTempClusterName))
		if name, ok := tempClusterName.(string); ok {
			klog.Infof("Deleting temporary kind cluster %s", name)
			var err error
			ctx, err = envfuncs.DestroyKindCluster(name)(ctx, cfg)
			if err != nil {
				return ctx, err
			}
		}
		return ctx, nil
	}
}
