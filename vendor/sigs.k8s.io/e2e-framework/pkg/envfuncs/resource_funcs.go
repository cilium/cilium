/*
Copyright 2022 The Kubernetes Authors.

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

package envfuncs

import (
	"context"

	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// SetupCRDs is provided as a helper env.Func handler that can be used to setup the CRDs that are required
// to process your controller code for testing. For additional control on resource creation handling, please
// use the decoder.ApplyWithManifestDir directly with suitable arguments to customize the behavior
func SetupCRDs(crdPath, pattern string) env.Func {
	return func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		r, err := resources.New(c.Client().RESTConfig())
		if err != nil {
			return ctx, err
		}
		return ctx, decoder.ApplyWithManifestDir(ctx, r, crdPath, pattern, []resources.CreateOption{})
	}
}

// TeardownCRDs is provided as a handler function that can be hooked into your test's teardown sequence to
// make sure that you can cleanup the CRDs that were setup as part of the SetupCRDs hook
func TeardownCRDs(crdPath, pattern string) env.Func {
	return func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		r, err := resources.New(c.Client().RESTConfig())
		if err != nil {
			return ctx, err
		}
		return ctx, decoder.DeleteWithManifestDir(ctx, r, crdPath, pattern, []resources.DeleteOption{})
	}
}
