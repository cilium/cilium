// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumcel "github.com/cilium/cilium/pkg/cel"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func filterByCELExpression(ctx context.Context, log *slog.Logger, exprs []string) (FilterFunc, error) {
	results := make([]ciliumcel.CompilationResult, 0, len(exprs))
	for _, expr := range exprs {
		r := ciliumcel.Env.Compile(ciliumcel.EnvTypeFlowFilter, expr)
		if r.Error != nil {
			return nil, fmt.Errorf("error compiling CEL expression: %w", r.Error)
		}
		results = append(results, r)
	}

	return func(ev *v1.Event) bool {
		for _, r := range results {
			match, err := r.Evaluate(ctx, ev.GetFlow())
			if err != nil {
				log.Error("error running CEL program", logfields.Error, err)
				return false
			}
			if match {
				return true
			}
		}
		return false
	}, nil
}

// CELExpressionFilter implements filtering based on CEL (common expression
// language) expressions
type CELExpressionFilter struct {
	log *slog.Logger
}

// OnBuildFilter builds a CEL expression filter.
func (t *CELExpressionFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	if exprs := ff.GetExperimental().GetCelExpression(); exprs != nil {
		filter, err := filterByCELExpression(ctx, t.log, exprs)
		if err != nil {
			return nil, err
		}
		return []FilterFunc{filter}, nil
	}
	return []FilterFunc{}, nil
}
