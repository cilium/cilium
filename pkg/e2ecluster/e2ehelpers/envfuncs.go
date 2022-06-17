// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package e2ehelpers

import (
	"context"

	"go.uber.org/multierr"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// Sequence returns an env.Func that calls the passed env.Funcs in order.
// Sequence stops when any error is encountered.
func Sequence(envFuncs ...env.Func) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		for _, envFunc := range envFuncs {
			var err error
			ctx, err = envFunc(ctx, cfg)
			if err != nil {
				return nil, err
			}
		}
		return ctx, nil
	}
}

// All runs all env.Funcs passed to it. Any errors are accumulated and returned.
func All(envFuncs ...env.Func) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var errs error
		for _, envFunc := range envFuncs {
			var err error
			ctx, err = envFunc(ctx, cfg)
			errs = multierr.Append(errs, err)
		}
		return ctx, errs
	}
}
