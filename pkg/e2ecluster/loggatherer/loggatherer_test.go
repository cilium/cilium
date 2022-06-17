// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !noe2emetatest

package loggatherer_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/cilium/pkg/e2ecluster/loggatherer"
)

var testenv env.Environment

func TestMain(m *testing.M) {
	cfg, err := envconf.NewFromFlags()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	testenv = env.NewWithConfig(cfg)

	kindClusterName := envconf.RandomName("loggatherer", 16)
	namespace := envconf.RandomName("kind-ns", 16)
	testenv.Setup(
		envfuncs.CreateKindCluster(kindClusterName),
		envfuncs.CreateNamespace(namespace),
		loggatherer.Setup(),
	)
	testenv.Finish(
		loggatherer.Finish(),
		envfuncs.DeleteNamespace(namespace),
		envfuncs.DestroyKindCluster(kindClusterName),
	)
	os.Exit(testenv.Run(m))
}

func TestLogGatherer(t *testing.T) {
	feature := features.New("LogGatherer").
		WithLabel("metatest", "true").
		Assess("Objects", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r, err := resources.New(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Get(ctx, "cilium-log-gatherer", "kube-system", &v1.ServiceAccount{}); err != nil {
				t.Error(err)
			}
			if err := r.Get(ctx, "log-gatherer", "kube-system", &appsv1.DaemonSet{}); err != nil {
				t.Error(err)
			}
			return ctx
		}).
		Feature()
	testenv.Test(t, feature)
}
