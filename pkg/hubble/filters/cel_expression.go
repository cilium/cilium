// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/google/cel-go/cel"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// unfortunately, "flow" conflicts with the protobuf package name "flow", so
	// we have to use something else.
	// TODO: what should this be?
	flowVariableName = "_flow"

	celTypes = cel.Types(&flowpb.Flow{})

	goBoolType = reflect.TypeOf(false)

	celEnv *cel.Env
)

func init() {
	var err error
	celEnv, err = cel.NewEnv(
		cel.Container("flow"),
		celTypes,
		cel.Variable(flowVariableName, cel.ObjectType("flow.Flow")),
	)
	if err != nil {
		panic(fmt.Sprintf("error creating CEL env %s", err))
	}

}

// compile will parse and check an expression `expr` against a given
// environment `env` and determine whether the resulting type of the expression
// matches the `exprType` provided as input.
// Copied from
// https://github.com/google/cel-go/blob/338b3c80e688f7f44661d163c0dbc02eb120dcb7/codelab/solution/codelab.go#LL385C1-L399C2
// with modifications
func compile(env *cel.Env, expr string, celType *cel.Type) (*cel.Ast, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	// Type-check the expression for correctness.
	checked, iss := env.Check(ast)
	// Report semantic errors, if present.
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	if checked.OutputType() != celType {
		return nil, fmt.Errorf(
			"got %q, wanted %q result type",
			checked.OutputType(), celType)
	}
	return ast, nil
}

func filterByCELExpression(ctx context.Context, log *slog.Logger, exprs []string) (FilterFunc, error) {
	var programs []cel.Program
	for _, expr := range exprs {
		// we want filters to be boolean expressions, so check the type of the
		// expression before proceeding
		ast, err := compile(celEnv, expr, cel.BoolType)
		if err != nil {
			return nil, fmt.Errorf("error compiling CEL expression: %w", err)
		}

		prg, err := celEnv.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("error building CEL program: %w", err)
		}
		programs = append(programs, prg)
	}

	return func(ev *v1.Event) bool {
		for _, prg := range programs {
			out, _, err := prg.ContextEval(ctx, map[string]any{
				flowVariableName: ev.GetFlow(),
			})
			if err != nil {
				log.Error("error running CEL program", logfields.Error, err)
				return false
			}

			v, err := out.ConvertToNative(goBoolType)
			if err != nil {
				log.Error("invalid conversion in CEL program", logfields.Error, err)
				return false
			}
			b, ok := v.(bool)
			if ok && b {
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
