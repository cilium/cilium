// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel

import (
	"context"
	"fmt"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cel/library"
	ciliumTypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/google/cel-go/cel"
)

// EnvType represents the kind of CEL environment, which determines the
// variables and functions available for use in expressions.
type EnvType string

const (
	EnvTypeLabelSelector EnvType = "LabelSelector"
	EnvTypeFlowFilter    EnvType = "FlowFilter"
)

var (
	baseCELEnvOpts = []cel.EnvOption{
		cel.EagerlyValidateDeclarations(true),
		cel.HomogeneousAggregateLiterals(),
	}

	celEnvironments = map[EnvType][]cel.EnvOption{
		EnvTypeLabelSelector: {
			cel.OptionalTypes(),
			library.LabelMatcher(),
		},
		EnvTypeFlowFilter: {
			library.FlowFilter(),
		},
	}

	// Env is the global static CEL environment that can be used
	// to compile CEL expressions.
	Env Environment = nil
)

func init() {
	// Initialize the environment with empty config to provide bare CEL
	// environments. The global environment should be reinitialized once
	// we construct Environment with user config and metrics.
	env, err := NewEnvironment(Config{
		CompilerCacheMaxEntries:        0,
		ExpressionMaxCost:              0,
		ProgramMaxCost:                 0,
		ProgramInterruptCheckFrequency: 0,
	}, nil)
	if err != nil {
		panic(fmt.Sprintf("Unable to create CEL environment: %s", err))
	}
	Env = env
}

var envInit sync.Once

func registerGlobalEnv(env Environment) {
	envInit.Do(func() {
		Env = env
	})
}

type Environment map[EnvType]*Compiler

func NewEnvironment(cfg Config, metrics *Metrics) (Environment, error) {
	env := make(map[EnvType]*Compiler)
	for kind, opts := range celEnvironments {
		compiler, err := NewCompiler(kind, cfg, metrics, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize complier for env %s: %w", kind, err)
		}

		env[kind] = compiler
	}
	return env, nil
}

func (e Environment) Compile(kind EnvType, expression string) CompilationResult {
	c, ok := e[kind]
	if !ok {
		return CompilationResult{
			Error: fmt.Errorf("uninitialized environment %s", kind),
		}
	}
	return c.Compile(expression)
}

// CompilationResult is a compiled CEL expression ready for repeated evaluation.
// It is safe for concurrent use once created.
type CompilationResult struct {
	EnvType EnvType

	Expression string
	Program    cel.Program
	OutputType *cel.Type
	Error      error

	// metrics is set by the Compiler and used to record evaluation timing.
	// May be nil when the Compiler was created without metrics.
	metrics *Metrics
}

// Evaluate evaluates the compiled expression against provided arg and returns whether
// the expression holds. Returns an error if the expression itself failed to
// compile or if evaluation produces a non-bool result.
func (r *CompilationResult) Evaluate(ctx context.Context, arg any) (bool, error) {
	if r.Error != nil {
		return false, r.Error
	}

	// Derive activation for the CEL program based on the environment type.
	activation := make(map[string]any)
	if arg != nil {
		switch r.EnvType {
		case EnvTypeLabelSelector:
			lm, ok := arg.(labels.LabelMatcher)
			if !ok {
				return false, fmt.Errorf("expected argument of type LabelMatcher got %T", arg)
			}
			activation[library.LabelMatcherVar] = ciliumTypes.NewLabelMatcher(lm)
		case EnvTypeFlowFilter:
			flow, ok := arg.(*flowpb.Flow)
			if !ok {
				return false, fmt.Errorf("expected argument of type Flow got %T", arg)
			}
			activation[library.FlowVarName] = flow
		default:
			return false, fmt.Errorf("invalid environment %s", r.EnvType)
		}
	}

	start := time.Now()
	out, _, err := r.Program.ContextEval(ctx, activation)
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %T, expected bool", out.Value())
	}

	if r.metrics != nil {
		r.metrics.EvaluationDuration.
			WithLabelValues(string(r.EnvType), metrics.Error2Outcome(err)).
			Observe(time.Since(start).Seconds())
	}
	return b, nil
}
