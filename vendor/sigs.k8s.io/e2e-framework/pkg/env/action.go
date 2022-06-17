/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package env

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/internal/types"
)

const (
	roleSetup = iota
	roleBeforeTest
	roleBeforeFeature
	roleAfterFeature
	roleAfterTest
	roleFinish
)

// action a group env functions
type action struct {
	role actionRole

	// funcs store the EnvFuncs used for setup/finish and before/after test.
	funcs []types.EnvFunc

	// featureFuncs store the FeatureEnvFunc for before/after feature.
	featureFuncs []types.FeatureEnvFunc

	// testFuncs store the TestEnvFunc for before/after feature.
	testFuncs []types.TestEnvFunc
}

// runWithT will run the action and inject *testing.T into the callback function.
func (a *action) runWithT(ctx context.Context, cfg *envconf.Config, t *testing.T) (context.Context, error) {
	switch a.role {
	case roleBeforeTest, roleAfterTest:
		if cfg.DryRunMode() {
			klog.V(2).Info("Skipping execution of roleBeforeTest and roleAfterTest due to framework being in dry-run mode")
			return ctx, nil
		}
		for _, f := range a.testFuncs {
			if f == nil {
				continue
			}

			var err error
			ctx, err = f(ctx, cfg, t)
			if err != nil {
				return ctx, err
			}
		}
	default:
		return ctx, fmt.Errorf("runWithT() is only valid for actions roleBeforeTest and roleAfterTest")
	}

	return ctx, nil
}

// runWithFeature will run the action and inject a FeatureInfo object into the callback function.
func (a *action) runWithFeature(ctx context.Context, cfg *envconf.Config, t *testing.T, fi types.Feature) (context.Context, error) {
	switch a.role {
	case roleBeforeFeature, roleAfterFeature:
		if cfg.DryRunMode() {
			klog.V(2).Info("Skipping execution of roleBeforeFeature and roleAfterFeature due to framework being in dry-run mode")
			return ctx, nil
		}
		for _, f := range a.featureFuncs {
			if f == nil {
				continue
			}

			var err error
			ctx, err = f(ctx, cfg, t, fi)
			if err != nil {
				return ctx, err
			}
		}
	default:
		return ctx, fmt.Errorf("runWithFeature() is only valid for actions roleBeforeFeature and roleAfterFeature")
	}
	return ctx, nil
}

func (a *action) run(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
	if cfg.DryRunMode() {
		klog.V(2).InfoS("Skipping processing of action due to framework being in dry-run mode")
		return ctx, nil
	}
	for _, f := range a.funcs {
		if f == nil {
			continue
		}

		var err error
		ctx, err = f(ctx, cfg)
		if err != nil {
			return ctx, err
		}
	}

	return ctx, nil
}
