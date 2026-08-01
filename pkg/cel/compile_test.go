// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cel"
	"github.com/cilium/cilium/pkg/labels"
)

func newEnv(t *testing.T) cel.Environment {
	t.Helper()
	env, err := cel.NewEnvironment(cel.DefaultConfig, nil)
	require.NoError(t, err)
	return env
}

func newEnvWithConfig(t *testing.T, cfg cel.Config) cel.Environment {
	t.Helper()
	env, err := cel.NewEnvironment(cfg, nil)
	require.NoError(t, err)
	return env
}

func TestEnvironmentCompile(t *testing.T) {
	env := newEnv(t)

	t.Run("valid bool expression", func(t *testing.T) {
		r := env.Compile(cel.EnvTypeLabelSelector, `label("k8s:app").hasValue()`)
		require.NoError(t, r.Error)
		require.NotNil(t, r.Program)
		require.NotNil(t, r.OutputType)
	})

	t.Run("compile error — syntax", func(t *testing.T) {
		r := env.Compile(cel.EnvTypeLabelSelector, `label(`)
		require.Error(t, r.Error)
	})

	t.Run("compile error — non-bool return", func(t *testing.T) {
		r := env.Compile(cel.EnvTypeLabelSelector, `label("k8s:app")`)
		require.Error(t, r.Error)
	})

	t.Run("compile error — unknown variable", func(t *testing.T) {
		r := env.Compile(cel.EnvTypeLabelSelector, `unknown_var == "x"`)
		require.Error(t, r.Error)
	})

	t.Run("compile error — invalid env kind", func(t *testing.T) {
		r := env.Compile("InvalidKind", `label("k8s:app").hasValue()`)
		require.Error(t, r.Error)
	})
}

func TestEvaluateCompilationResult(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		expr    string
		matcher labels.LabelMatcher
		want    bool
	}{
		{
			name:    "literal key present",
			expr:    `label("k8s:app").hasValue()`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    true,
		},
		{
			name:    "literal key absent",
			expr:    `label("k8s:missing").hasValue()`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    false,
		},
		{
			name:    "value equality match",
			expr:    `label("k8s:app") == optional.of("myapp")`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    true,
		},
		{
			name:    "value equality no match",
			expr:    `label("k8s:app") == optional.of("other")`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    false,
		},
		{
			name:    "any source matches k8s label",
			expr:    `label("any:app").hasValue()`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    true,
		},
		{
			name:    "conjunction both present",
			expr:    `label("k8s:app").hasValue() && label("k8s:env").hasValue()`,
			matcher: labels.K8sSet{"app": "myapp", "env": "prod"},
			want:    true,
		},
		{
			name:    "conjunction one absent",
			expr:    `label("k8s:app").hasValue() && label("k8s:env").hasValue()`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    false,
		},
		{
			name:    "exists over variable list",
			expr:    `["k8s:app", "k8s:missing"].exists(k, label(k).hasValue())`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    true,
		},
		{
			name:    "all over variable list true",
			expr:    `["k8s:app", "k8s:env"].all(k, label(k).hasValue())`,
			matcher: labels.K8sSet{"app": "myapp", "env": "prod"},
			want:    true,
		},
		{
			name:    "all over variable list false",
			expr:    `["k8s:app", "k8s:env"].all(k, label(k).hasValue())`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    false,
		},
		{
			name:    "orValue default for absent label",
			expr:    `label("k8s:missing").orValue("default") == "default"`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    true,
		},
		{
			name:    "string prefix match",
			expr:    `label("k8s:app").hasValue() && label("k8s:app").value().startsWith("my")`,
			matcher: labels.K8sSet{"app": "myapp"},
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := env.Compile(cel.EnvTypeLabelSelector, tc.expr)
			require.NoError(t, r.Error)
			got, err := r.Evaluate(ctx, tc.matcher)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestCompilerExpressionCost(t *testing.T) {
	// label("k8s:app").hasValue() has static MaxCost=4; reject when limit=3.
	env := newEnvWithConfig(t, cel.Config{
		ExpressionMaxCost:       3,
		ProgramMaxCost:          0,
		CompilerCacheMaxEntries: 16,
	})
	res := env.Compile(cel.EnvTypeLabelSelector, `label("k8s:app").hasValue()`)
	require.Error(t, res.Error)
	require.Contains(t, res.Error.Error(), "exceeds limit")

	// Allow exactly at the limit: single hasValue has MaxCost=4; allow 4.
	env = newEnvWithConfig(t, cel.Config{
		ExpressionMaxCost:       4,
		ProgramMaxCost:          0,
		CompilerCacheMaxEntries: 16,
	})
	res = env.Compile(cel.EnvTypeLabelSelector, `label("k8s:app").hasValue()`)
	require.NoError(t, res.Error)

	// label("k8s:app").hasValue() has runtime cost=4; reject when limit=3.
	env = newEnvWithConfig(t, cel.Config{
		ExpressionMaxCost:       0,
		ProgramMaxCost:          3,
		CompilerCacheMaxEntries: 16,
	})
	ctx := context.Background()
	res = env.Compile(cel.EnvTypeLabelSelector, `label("k8s:app").hasValue()`)
	require.NoError(t, res.Error)
	_, err := res.Evaluate(ctx, labels.K8sSet{"app": "myapp"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cost limit exceeded")

	env = newEnvWithConfig(t, cel.Config{
		ExpressionMaxCost:       0,
		ProgramMaxCost:          0,
		CompilerCacheMaxEntries: 16,
	})
	ctx = context.Background()
	res = env.Compile(cel.EnvTypeLabelSelector, `label("k8s:app").hasValue()`)
	require.NoError(t, res.Error)
	got, err := res.Evaluate(ctx, labels.K8sSet{"app": "myapp"})
	require.NoError(t, err)
	require.True(t, got)
}

func BenchmarkCompile(b *testing.B) {
	env, err := cel.NewEnvironment(cel.DefaultConfig, nil)
	require.NoError(b, err)

	exprs := []string{
		`label("k8s:app").hasValue()`,
		`label("k8s:app") == optional.of("myapp") && label("k8s:env").hasValue()`,
		`["k8s:app","k8s:env","k8s:tier"].all(k, label(k).hasValue())`,
	}
	for _, expr := range exprs {
		b.Run(expr, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r := env.Compile(cel.EnvTypeLabelSelector, expr)
				require.NoError(b, r.Error)
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	env, err := cel.NewEnvironment(cel.DefaultConfig, nil)
	require.NoError(b, err)

	matcher := labels.K8sSet{"app": "myapp", "env": "prod", "tier": "frontend"}
	ctx := context.Background()
	exprs := []string{
		`label("k8s:app").hasValue()`,
		`label("k8s:app") == optional.of("myapp") && label("k8s:env").hasValue()`,
		`["k8s:app","k8s:env","k8s:tier"].all(k, label(k).hasValue())`,
	}
	for _, expr := range exprs {
		r := env.Compile(cel.EnvTypeLabelSelector, expr)
		require.NoError(b, r.Error)

		b.Run(expr, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := r.Evaluate(ctx, matcher)
				require.NoError(b, err)
			}
		})
	}
}
