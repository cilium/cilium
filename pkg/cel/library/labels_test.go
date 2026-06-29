// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	"github.com/cilium/cilium/pkg/cel/library"
	ciliumCelTypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
)

// testLabelMatcher compiles and evaluates a CEL expression against the given LabelMatcher.
// It asserts on expected compile errors, runtime errors, or result values.
func testLabelMatcher(
	t *testing.T,
	expr string,
	matcher labels.LabelMatcher,
	expectResult ref.Val,
	expectRuntimeErr string,
	expectCompileErrs []string,
) {
	t.Helper()
	testCEL(t,
		[]cel.EnvOption{library.LabelMatcher(), cel.OptionalTypes()},
		library.LabelMatcherVar,
		expr,
		ciliumCelTypes.NewLabelMatcher(matcher),
		expectResult, expectRuntimeErr, expectCompileErrs,
	)
}

// labelsMap builds a labels.Labels map.
func labelsMap(src, key, val string) labels.Labels {
	return labels.Labels{
		key: labels.NewLabel(key, val, src),
	}
}

func TestLabelMatcher(t *testing.T) {
	cases := []struct {
		name              string
		expr              string
		matcher           labels.LabelMatcher
		expectResult      ref.Val
		expectRuntimeErr  string
		expectCompileErrs []string
	}{
		// Literal key, label present
		{
			name:         "k8s literal key found returns optional.of",
			expr:         `label("k8s:app") == optional.of("myapp")`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "k8s literal key value equality",
			expr:         `label("k8s:app").value() == "myapp"`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "k8s literal key hasValue true",
			expr:         `label("k8s:app").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},

		// Literal key, label absent
		{
			name:         "missing literal key returns optional.none",
			expr:         `label("k8s:missing") == optional.none()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "missing literal key hasValue false",
			expr:         `label("k8s:missing").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: falseVal,
		},

		// Source handling
		{
			name:         "any source matches k8s label",
			expr:         `label("any:app").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "any source returns correct value",
			expr:         `label("any:app") == optional.of("myapp")`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:    "reserved source does not match k8s label",
			expr:    `label("reserved:host").hasValue()`,
			matcher: labels.K8sSet{"host": "myhost"},
			// K8sSet only matches k8s or any source, not reserved
			expectResult: falseVal,
		},
		{
			name:         "no-source label defaults to any source",
			expr:         `label("app").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},

		// Labels map implementation
		// labels.Labels.LookupLabel matches on key+source+value, so a lookup label
		// with an empty value only matches stored labels that also have an empty value.
		{
			name:         "labels.Labels k8s source found (empty value)",
			expr:         `label("k8s:env").hasValue()`,
			matcher:      labelsMap(labels.LabelSourceK8s, "env", ""),
			expectResult: trueVal,
		},
		{
			name:         "labels.Labels wrong source returns none",
			expr:         `label("reserved:env").hasValue()`,
			matcher:      labelsMap(labels.LabelSourceK8s, "env", ""),
			expectResult: falseVal,
		},

		// LabelArray implementation
		{
			name:         "LabelArray found",
			expr:         `label("k8s:tier").value() == "frontend"`,
			matcher:      labels.LabelArray{labels.NewLabel("tier", "frontend", labels.LabelSourceK8s)},
			expectResult: trueVal,
		},
		{
			name:         "LabelArray not found",
			expr:         `label("k8s:missing").hasValue()`,
			matcher:      labels.LabelArray{labels.NewLabel("tier", "frontend", labels.LabelSourceK8s)},
			expectResult: falseVal,
		},

		// Conditional and boolean logic
		{
			name:         "label present AND value matches",
			expr:         `label("k8s:app").hasValue() && label("k8s:app").value() == "myapp"`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "label missing OR fallback",
			expr:         `label("k8s:missing").hasValue() || label("k8s:app").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "multiple label presence check",
			expr:         `label("k8s:app").hasValue() && label("k8s:env").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp", "env": "prod"},
			expectResult: trueVal,
		},
		{
			name:         "one label absent makes conjunction false",
			expr:         `label("k8s:app").hasValue() && label("k8s:missing").hasValue()`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: falseVal,
		},

		// String operations on optional value
		{
			name:         "value startsWith",
			expr:         `label("k8s:app").value().startsWith("my")`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "value endsWith",
			expr:         `label("k8s:app").value().endsWith("app")`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "value contains",
			expr:         `label("k8s:app").value().contains("ya")`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "value concatenation across labels",
			expr:         `label("k8s:app").value() + "-" + label("k8s:env").value() == "myapp-prod"`,
			matcher:      labels.K8sSet{"app": "myapp", "env": "prod"},
			expectResult: trueVal,
		},

		// Comprehensions with variable key
		{
			name:         "exists with variable key - one present",
			expr:         `["k8s:app", "k8s:missing"].exists(k, label(k).hasValue())`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "exists with variable key - none present",
			expr:         `["k8s:missing1", "k8s:missing2"].exists(k, label(k).hasValue())`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: falseVal,
		},
		{
			name:         "all with variable key - all present",
			expr:         `["k8s:app", "k8s:env"].all(k, label(k).hasValue())`,
			matcher:      labels.K8sSet{"app": "myapp", "env": "prod"},
			expectResult: trueVal,
		},
		{
			name:         "all with variable key - one absent",
			expr:         `["k8s:app", "k8s:env"].all(k, label(k).hasValue())`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: falseVal,
		},
		{
			name:         "exists with value match",
			expr:         `["k8s:app", "k8s:env"].exists(k, label(k) == optional.of("prod"))`,
			matcher:      labels.K8sSet{"app": "myapp", "env": "prod"},
			expectResult: trueVal,
		},
		{
			name:         "filter labels by presence",
			expr:         `["k8s:app", "k8s:missing", "k8s:env"].filter(k, label(k).hasValue()) == ["k8s:app", "k8s:env"]`,
			matcher:      labels.K8sSet{"app": "myapp", "env": "prod"},
			expectResult: trueVal,
		},
		{
			name:         "map label values",
			expr:         `["k8s:app", "k8s:env"].map(k, label(k).value()) == ["myapp", "prod"]`,
			matcher:      labels.K8sSet{"app": "myapp", "env": "prod"},
			expectResult: trueVal,
		},

		// Empty label set
		{
			name:         "empty matcher returns none for any key",
			expr:         `label("k8s:app").hasValue()`,
			matcher:      labels.K8sSet{},
			expectResult: falseVal,
		},
		{
			name:         "exists on empty matcher is false",
			expr:         `["k8s:app", "k8s:env"].exists(k, label(k).hasValue())`,
			matcher:      labels.K8sSet{},
			expectResult: falseVal,
		},

		// Ternary / optional.or
		{
			name:         "optional.orValue provides default",
			expr:         `label("k8s:missing").orValue("default") == "default"`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "optional.orValue with present label returns original",
			expr:         `label("k8s:app").orValue("default") == "myapp"`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},

		// Set membership — In / NotIn
		{
			name:         "value in set — match",
			expr:         `label("k8s:env").value() in ["prod", "staging", "dev"]`,
			matcher:      labels.K8sSet{"env": "prod"},
			expectResult: trueVal,
		},
		{
			name:         "value in set — no match",
			expr:         `label("k8s:env").value() in ["prod", "staging", "dev"]`,
			matcher:      labels.K8sSet{"env": "canary"},
			expectResult: falseVal,
		},
		{
			name:         "value not in set — match",
			expr:         `!(label("k8s:env").value() in ["prod", "staging"])`,
			matcher:      labels.K8sSet{"env": "canary"},
			expectResult: trueVal,
		},
		{
			name:         "value not in set — no match",
			expr:         `!(label("k8s:env").value() in ["prod", "staging"])`,
			matcher:      labels.K8sSet{"env": "prod"},
			expectResult: falseVal,
		},
		{
			name:         "orValue fallback in set — absent label uses default which is in set",
			expr:         `label("k8s:tier").orValue("frontend") in ["frontend", "backend"]`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: trueVal,
		},
		{
			name:         "orValue fallback not in set — absent label uses default which is not in set",
			expr:         `label("k8s:tier").orValue("sidecar") in ["frontend", "backend"]`,
			matcher:      labels.K8sSet{"app": "myapp"},
			expectResult: falseVal,
		},
		{
			name:         "present label value in set overrides orValue default",
			expr:         `label("k8s:tier").orValue("sidecar") in ["frontend", "backend"]`,
			matcher:      labels.K8sSet{"tier": "backend"},
			expectResult: trueVal,
		},

		// Compile errors
		{
			name:              "label with no arguments is a compile error",
			expr:              `label()`,
			matcher:           labels.K8sSet{},
			expectCompileErrs: []string{"undeclared reference"},
		},
		{
			name:              "label with two arguments is a compile error",
			expr:              `label("k8s:app", "extra")`,
			matcher:           labels.K8sSet{},
			expectCompileErrs: []string{"undeclared reference"},
		},
		{
			name:              "invalid access to internal @label_matcher variable",
			expr:              `@label_matcher.someField`,
			matcher:           labels.K8sSet{},
			expectCompileErrs: []string{"Syntax error: token recognition error at: '@'"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testLabelMatcher(t, tc.expr, tc.matcher, tc.expectResult, tc.expectRuntimeErr, tc.expectCompileErrs)
		})
	}
}
