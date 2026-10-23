// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/labels"
)

// benchRuleOrigin builds a rule origin of a size typical of a churned policy:
// one rule label per contributing rule, plus the per-rule log strings that
// ruleOrigin.LogString() serialises.
func benchRuleOrigin(prefix string, rules int) ruleOrigin {
	lbls := make(labels.LabelArrayList, 0, rules)
	logs := make([]string, 0, rules)
	for i := range rules {
		lbls = append(lbls, labels.ParseLabelArray(
			fmt.Sprintf("k8s:io.cilium.k8s.policy.name=%s-policy-%d", prefix, i),
			fmt.Sprintf("k8s:io.cilium.k8s.policy.namespace=%s", prefix),
		))
		logs = append(logs, fmt.Sprintf("%s rule %d selected the endpoint", prefix, i))
	}
	return makeRuleOrigin(lbls, logs)
}

// BenchmarkMapStateEntryEqual measures the comparison addKeyWithChanges performs
// for every policy map entry of every endpoint regeneration.
//
// Equal is `e.equivalent(o) && e.derivedFromRules == o.derivedFromRules`, and
// equivalent's last clause falls back to comparing ruleOrigin.LogString(),
// which json.Marshals both origins. When the interned origin handles differ
// that marshalling runs and then Equal returns false on the handle comparison
// anyway, so the work cannot affect the result. The differing-origins case
// below is the one that regressed; same-origins short-circuits and is the
// control.
func BenchmarkMapStateEntryEqual(b *testing.B) {
	for _, rules := range []int{1, 8, 32} {
		base := newMapStateEntry(0, 0, 0, NilRuleOrigin, 0, 0, 0)

		left := base
		left.derivedFromRules = benchRuleOrigin("a", rules)
		sameOrigin := left
		differentOrigin := base
		differentOrigin.derivedFromRules = benchRuleOrigin("b", rules)

		b.Run(fmt.Sprintf("rules=%d/same-origins", rules), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if !left.Equal(sameOrigin) {
					b.Fatal("entries with identical origins must compare equal")
				}
			}
		})

		b.Run(fmt.Sprintf("rules=%d/differing-origins", rules), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if left.Equal(differentOrigin) {
					b.Fatal("entries with differing origins must not compare equal")
				}
			}
		})
	}
}

// BenchmarkRuleOriginLogString isolates the json.Marshal that the comparison
// above reaches, so the two can be attributed separately. equivalent() has
// callers of its own that legitimately want label-insensitive equality, and
// they still pay this.
func BenchmarkRuleOriginLogString(b *testing.B) {
	for _, rules := range []int{1, 8, 32} {
		origin := benchRuleOrigin("a", rules)
		b.Run(fmt.Sprintf("rules=%d", rules), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if origin.LogString() == "" {
					b.Fatal("expected a non-empty log string")
				}
			}
		})
	}
}
