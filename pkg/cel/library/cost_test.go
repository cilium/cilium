// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cel/library"
	ciliumTypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
)

// testLabelMatcherCost compiles expr, verifies the static cost estimate matches expectStaticCost,
// then evaluates against matcher and verifies the actual runtime cost matches
// expectRuntimeCost.
func testLabelMatcherCost(t *testing.T, expr string, matcher labels.LabelMatcher, expectStaticCost checker.CostEstimate, expectRuntimeCost uint64) {
	t.Helper()

	env, err := cel.NewEnv(library.LabelMatcher(), cel.OptionalTypes())
	require.NoError(t, err)

	ast, issues := env.Compile(expr)
	require.Nil(t, issues)

	est := library.CostEstimator{}
	actualCost, err := env.EstimateCost(ast, est)
	require.NoError(t, err)
	require.Equal(t, expectStaticCost, actualCost)

	prog, err := env.Program(ast, cel.CostTracking(est))
	require.NoError(t, err)

	lm := ciliumTypes.NewLabelMatcher(matcher)
	_, details, err := prog.Eval(map[string]any{library.LabelMatcherVar: lm})
	require.NoError(t, err)
	require.Equal(t, expectRuntimeCost, *details.ActualCost())
}

// TestLiteralLabelLookupCost covers the common path where label() is called with
// a string literal. The macro expands to:
// __label_matcher_lookup_label__(@label_matcher, __label_make__(source, key))
// giving a base lookup cost of @label_matcher(1) + label_make(1) + lookup_label(1) = 3.
func TestLabelMatcherLiteralLabelLookupCost(t *testing.T) {
	cases := []struct {
		name              string
		expr              string
		matcher           labels.LabelMatcher
		expectStaticCost  checker.CostEstimate
		expectRuntimeCost uint64
	}{
		{
			// @label_matcher(1) + label_make(1) + lookup_label(1) + hasValue()(1) = 4.
			name:              "label present",
			expr:              `label("k8s:app").hasValue()`,
			matcher:           labels.K8sSet{"app": "myapp"},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 4},
			expectRuntimeCost: 4,
		},
		{
			// Lookup cost is unconditional regardless of label presence.
			// @label_matcher(1) + label_make(1) + lookup_label(1) + hasValue()(1) = 4.
			name:              "label absent — same cost as present",
			expr:              `label("k8s:missing").hasValue()`,
			matcher:           labels.K8sSet{"app": "myapp"},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 4},
			expectRuntimeCost: 4,
		},
		{
			// lookup(3) + value()(1) = 4; result size bounded by {0,63}; "myapp" size=5;
			// == cost = ceil(min(63,5)*0.1) = 1; total = 5.
			name:              "value equality via .value()",
			expr:              `label("k8s:app").value() == "myapp"`,
			matcher:           labels.K8sSet{"app": "myapp"},
			expectStaticCost:  checker.CostEstimate{Min: 5, Max: 5},
			expectRuntimeCost: 5,
		},
		{
			// Static: lookup(3) + orValue()(1) = 4; result size bounded by {0,63}; "myapp" size=5;
			// == cost = ceil(min(63,5)*0.1) = 1; total = 5.
			// Runtime: label is present; orValue unwraps directly (0 cost); "myapp"=="myapp"
			// ceil(5*0.1) = 1; total = 3+0+1 = 4.
			name:              "orValue on absent label",
			expr:              `label("k8s:app").orValue("default") == "myapp"`,
			matcher:           labels.K8sSet{"app": "myapp"},
			expectStaticCost:  checker.CostEstimate{Min: 5, Max: 5},
			expectRuntimeCost: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testLabelMatcherCost(t, tc.expr, tc.matcher, tc.expectStaticCost, tc.expectRuntimeCost)
		})
	}
}

func TestLabelMatcherBooleanCompositionCost(t *testing.T) {
	cases := []struct {
		name              string
		expr              string
		matcher           labels.LabelMatcher
		expectStaticCost  checker.CostEstimate
		expectRuntimeCost uint64
	}{
		{
			// Each label(...).hasValue() costs 4; min=4: && short-circuits after false LHS,
			// max=8: both arms evaluated (4+4).
			// Both present → no short-circuit; runtime = 8.
			name:              "full '&&' evaluation",
			expr:              `label("k8s:app").hasValue() && label("k8s:env").hasValue()`,
			matcher:           labels.K8sSet{"app": "myapp", "env": "prod"},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 8},
			expectRuntimeCost: 8,
		},
		{
			// "k8s:app" absent → hasValue() returns false → && short-circuits;
			// only the LHS (cost 4) is evaluated; runtime = 4.
			name:              "short circuit '&&' evaluation",
			expr:              `label("k8s:app").hasValue() && label("k8s:env").hasValue()`,
			matcher:           labels.K8sSet{"env": "prod"},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 8},
			expectRuntimeCost: 4,
		},
		{
			// Empty matcher → "k8s:app" absent → hasValue() returns false → && short-circuits;
			// only the LHS (cost 4) is evaluated; runtime = 4.
			name:              "short circuit '&&' evaluation(empty matcher)",
			expr:              `label("k8s:app").hasValue() && label("k8s:env").hasValue()`,
			matcher:           labels.K8sSet{},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 8},
			expectRuntimeCost: 4,
		},

		{
			// Each label(...).hasValue() costs 4; min=4: || short-circuits after true LHS,
			// max=8: both arms evaluated (4+4).
			// "k8s:app" absent → LHS false → evaluates RHS too; runtime = 8.
			name:              "full '||' evaluation",
			expr:              `label("k8s:app").hasValue() || label("k8s:env").hasValue()`,
			matcher:           labels.K8sSet{"env": "prod"},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 8},
			expectRuntimeCost: 8,
		},
		{
			// "k8s:app" present → hasValue() returns true → || short-circuits;
			// only the LHS (cost 4) is evaluated; runtime = 4.
			name:              "short circuit '||' evaluation",
			expr:              `label("k8s:app").hasValue() || label("k8s:env").hasValue()`,
			matcher:           labels.K8sSet{"app": "myapp"},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 8},
			expectRuntimeCost: 4,
		},
		{
			// Empty matcher → both labels absent → neither arm short-circuits;
			// both arms evaluated (4+4); runtime = 8.
			name:              "full '||' evaluation(empty matcher)",
			expr:              `label("k8s:app").hasValue() || label("k8s:env").hasValue()`,
			matcher:           labels.K8sSet{},
			expectStaticCost:  checker.CostEstimate{Min: 4, Max: 8},
			expectRuntimeCost: 8,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testLabelMatcherCost(t, tc.expr, tc.matcher, tc.expectStaticCost, tc.expectRuntimeCost)
		})
	}
}

// TestDynamicKeyLookupCost covers the path where label() receives a non-literal
// argument (e.g. a comprehension variable). The macro emits a call to the
// __label_matcher_lookup_key__ overload which parses the label string at runtime.
func TestLabelMatcherDynamicKeyLookupCost(t *testing.T) {
	cases := []struct {
		name              string
		expr              string
		matcher           labels.LabelMatcher
		expectStaticCost  checker.CostEstimate
		expectRuntimeCost uint64
	}{
		{
			// Comprehension base overhead = 10; per-iter body: ident(k)(1) + lookup_key(2) + hasValue()(1) = 4.
			// 1 element: min = 10+4 = 14; max = 19 (comprehension wrapping adds overhead to max).
			// "k8s:app" present, single iteration runs fully; runtime = 19.
			name:              "all over single-element list",
			expr:              `["k8s:app"].all(k, label(k).hasValue())`,
			matcher:           labels.K8sSet{"app": "myapp"},
			expectStaticCost:  checker.CostEstimate{Min: 14, Max: 19},
			expectRuntimeCost: 19,
		},
		{
			// 2-element list; each additional element adds min-iter cost (3) to min and
			// max-iter cost (8) to max over the 1-element baseline: min=14+3=17, max=19+8=27.
			// Both present, no short-circuit; all 2 iterations run; runtime = 27.
			name:              "all over two-element list — both present",
			expr:              `["k8s:app", "k8s:env"].all(k, label(k).hasValue())`,
			matcher:           labels.K8sSet{"app": "myapp", "env": "prod"},
			expectStaticCost:  checker.CostEstimate{Min: 17, Max: 27},
			expectRuntimeCost: 27,
		},
		{
			// exists macro has slightly higher overhead than all (+2 min, +2 max vs all 2-elem):
			// min=19, max=29.
			// "k8s:app" present → first iteration matches → short-circuits, skipping second
			// iteration body; runtime = 23.
			name:              "exists over two-element list — first matches",
			expr:              `["k8s:app", "k8s:env"].exists(k, label(k).hasValue())`,
			matcher:           labels.K8sSet{"app": "myapp", "env": "prod"},
			expectStaticCost:  checker.CostEstimate{Min: 19, Max: 29},
			expectRuntimeCost: 23,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testLabelMatcherCost(t, tc.expr, tc.matcher, tc.expectStaticCost, tc.expectRuntimeCost)
		})
	}
}

// testFlowFilterCost compiles expr, checks its static cost estimate, then evaluates
// it against flow and checks the actual runtime cost.
func testFlowFilterCost(t *testing.T, expr string, flow *flowpb.Flow, wantStatic checker.CostEstimate, wantRuntime uint64) {
	t.Helper()
	env, err := cel.NewEnv(library.FlowFilter())
	require.NoError(t, err)

	ast, issues := env.Compile(expr)
	require.NoError(t, issues.Err())

	est := library.CostEstimator{}
	gotStatic, err := env.EstimateCost(ast, est)
	require.NoError(t, err)
	require.Equal(t, wantStatic, gotStatic)

	prog, err := env.Program(ast, cel.CostTracking(est))
	require.NoError(t, err)

	_, details, err := prog.Eval(map[string]any{library.FlowVarName: flow})
	require.NoError(t, err)
	require.Equal(t, wantRuntime, *details.ActualCost())
}

func TestFlowFilterCostEstimation(t *testing.T) {
	// Cost calculation:
	//   ident access    = 1
	//   field select    = 1 per level
	//   int/enum ==     = 1
	//   string == (n)   = ceil(n * 0.1), where n = min(len(lhs), len(rhs))
	//   &&/|| min cost  = cost of left operand only (short-circuit)
	//   &&/|| max cost  = cost of both operands

	tests := []struct {
		name        string
		expr        string
		flow        *flowpb.Flow
		wantStatic  checker.CostEstimate
		wantRuntime uint64
	}{
		{
			// _flow(1) + .verdict(1) + ==(1) = 3; 0 is a constant (0).
			name:        "verdict int comparison",
			expr:        `_flow.verdict == 0`,
			flow:        &flowpb.Flow{Verdict: flowpb.Verdict_VERDICT_UNKNOWN},
			wantStatic:  checker.CostEstimate{Min: 3, Max: 3},
			wantRuntime: 3,
		},
		{
			// _flow(1) + .verdict(1) + Verdict ident(1) + ==(1) = 4.
			// At runtime Verdict.FORWARDED is a constant (0), so runtime = 3.
			name:        "verdict enum comparison",
			expr:        `_flow.verdict == Verdict.FORWARDED`,
			flow:        &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED},
			wantStatic:  checker.CostEstimate{Min: 4, Max: 4},
			wantRuntime: 3,
		},
		{
			// _flow(1) + .l4(1) + has()(1) = 3.
			name:        "l4 TCP presence check",
			expr:        `has(_flow.l4.TCP)`,
			flow:        &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}}},
			wantStatic:  checker.CostEstimate{Min: 3, Max: 3},
			wantRuntime: 3,
		},
		{
			// has(_flow.l4.TCP) costs 3; false short-circuits &&, so min=3.
			// Full RHS: _flow(1)+.l4(1)+.TCP(1)+.destination_port(1)+uint(1)+==(1) = 6; max=3+6=9.
			name:        "l4 TCP presence with port check — short-circuit skips RHS",
			expr:        `has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(80)`,
			flow:        &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}}},
			wantStatic:  checker.CostEstimate{Min: 3, Max: 9},
			wantRuntime: 9, // has() is true, so RHS is also evaluated
		},
		{
			// _flow(1)+.IP(1)+.source(1) = 3 arg cost; '1.1.1.1' size=7.
			// string == cost = ceil(min(7, maxUnknown) * 0.1) = ceil(7*0.1) = 1; total = 4.
			name:        "IP source string comparison",
			expr:        `_flow.IP.source == '1.1.1.1'`,
			flow:        &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1"}},
			wantStatic:  checker.CostEstimate{Min: 4, Max: 4},
			wantRuntime: 4,
		},
		{
			// First || arm costs 4; true short-circuits, so min=4.
			// If false, second arm also evaluated: 4+4=8; max=8.
			// Runtime: first comparison matches → short-circuits at 3 (enum constant folded).
			name:        "verdict OR — short-circuit on first match",
			expr:        `_flow.verdict == Verdict.FORWARDED || _flow.verdict == Verdict.TRANSLATED`,
			flow:        &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED},
			wantStatic:  checker.CostEstimate{Min: 4, Max: 8},
			wantRuntime: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testFlowFilterCost(t, tc.expr, tc.flow, tc.wantStatic, tc.wantRuntime)
		})
	}
}
