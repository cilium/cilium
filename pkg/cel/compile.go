// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"k8s.io/utils/keymutex"
	"k8s.io/utils/lru"

	"github.com/cilium/cilium/pkg/cel/library"
	"github.com/cilium/cilium/pkg/metrics"
)

// Compiler compiles CEL expressions against the label matcher environment.
// A single Compiler (and its underlying cel.Env) is safe for concurrent use.
type Compiler struct {
	cfg     Config
	metrics *Metrics

	envType EnvType
	env     *cel.Env

	compileMutex keymutex.KeyMutex

	cache      *lru.Cache
	cacheMutex sync.RWMutex
}

// NewCompiler creates a Compiler for the given environment type.
// Metrics may be nil to disable metric recording.
func NewCompiler(envType EnvType, cfg Config, metrics *Metrics, opts ...cel.EnvOption) (*Compiler, error) {
	// Construct base environment
	// TODO: Only need to do once for Base environment.
	baseEnv, err := cel.NewEnv(baseCELEnvOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create base CEL environment: %w", err)
	}

	// Extend the CEL environment with custom options for the provided environment.
	env, err := baseEnv.Extend(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	var compilerCache *lru.Cache = nil
	if cfg.CompilerCacheEnabled() {
		compilerCache = lru.New(cfg.CompilerCacheMaxEntries)
	}
	return &Compiler{
		cfg:          cfg,
		metrics:      metrics,
		envType:      envType,
		env:          env,
		compileMutex: keymutex.NewHashed(0),
		cache:        compilerCache,
	}, nil
}

// Compile parses, type-checks, and plans a CEL expression.
// The expression must evaluate to a boolean type.
func (c *Compiler) Compile(expression string) CompilationResult {
	// Compiling a CEL expression is expensive enough that it is cheaper
	// to lock a mutex than doing it several times in parallel.
	c.compileMutex.LockKey(expression)
	//nolint:errcheck // Only returns an error for unknown keys, which isn't the case here.
	defer c.compileMutex.UnlockKey(expression)

	cached := c.getFromCache(expression)
	if cached != nil {
		return *cached
	}

	start := time.Now()
	result := c.compile(expression)
	if c.metrics != nil {
		c.metrics.CompilationDuration.
			WithLabelValues(string(c.envType), metrics.Error2Outcome(result.Error)).
			Observe(time.Since(start).Seconds())
	}
	if result.Error == nil {
		c.addToCache(expression, &result)
	}
	return result
}

func (c *Compiler) compile(expression string) (result CompilationResult) {
	result.EnvType = c.envType
	result.Expression = expression

	ast, issues := c.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		result.Error = issues.Err()
		return
	}

	outputType := ast.OutputType()
	if outputType != cel.BoolType {
		result.Error = fmt.Errorf("expression must return bool, got %s", ast.OutputType())
		return
	}

	if _, err := cel.AstToCheckedExpr(ast); err != nil {
		result.Error = fmt.Errorf("unexpected AST check error: %w", err)
		return
	}

	costEst, err := c.env.EstimateCost(ast, library.CostEstimator{})
	if err != nil {
		result.Error = fmt.Errorf("cost estimation: %w", err)
		return
	}

	if c.cfg.ExpressionMaxCost > 0 && costEst.Max > c.cfg.ExpressionMaxCost {
		result.Error = fmt.Errorf("expression max cost %d exceeds limit %d", costEst.Max, c.cfg.ExpressionMaxCost)
		return
	}

	progOpts := []cel.ProgramOption{
		cel.CostTracking(library.CostEstimator{}),
		cel.EvalOptions(cel.OptOptimize),
	}
	if c.cfg.ProgramMaxCost > 0 {
		progOpts = append(progOpts, cel.CostLimit(c.cfg.ProgramMaxCost))
	}
	if c.cfg.ProgramInterruptCheckFrequency > 0 {
		progOpts = append(progOpts, cel.InterruptCheckFrequency(c.cfg.ProgramInterruptCheckFrequency))
	}

	prog, err := c.env.Program(ast, progOpts...)
	if err != nil {
		return CompilationResult{Expression: expression, Error: fmt.Errorf("program creation: %w", err)}
	}

	result.Program = prog
	result.OutputType = outputType
	result.metrics = c.metrics

	return
}

func (c *Compiler) addToCache(expression string, expr *CompilationResult) {
	if !c.cfg.CompilerCacheEnabled() {
		return
	}

	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	c.cache.Add(expression, expr)
}

func (c *Compiler) getFromCache(expression string) *CompilationResult {
	if !c.cfg.CompilerCacheEnabled() {
		return nil
	}

	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	expr, found := c.cache.Get(expression)
	if !found {
		return nil
	}
	return expr.(*CompilationResult)
}
