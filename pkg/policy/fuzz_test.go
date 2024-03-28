// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		label, err := ff.GetString()
		if err != nil {
			return
		}
		fromBar := &SearchContext{From: labels.ParseSelectLabelArray(label)}
		r := api.Rule{}
		err = ff.GenerateStruct(&r)
		if err != nil {
			return
		}
		err = r.Sanitize()
		if err != nil {
			return
		}
		rule := &rule{Rule: r}
		state := traceState{}
		_, _ = rule.resolveEgressPolicy(testPolicyContext, fromBar, &state, L4PolicyMap{}, nil, nil)

	})
}
