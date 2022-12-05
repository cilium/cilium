// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzCiliumNetworkPolicyParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		r := &CiliumNetworkPolicy{}
		ff.GenerateStruct(r)
		_, _ = r.Parse()
	})
}

func FuzzCiliumClusterwideNetworkPolicyParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		r := &CiliumClusterwideNetworkPolicy{}
		ff.GenerateStruct(r)
		_, _ = r.Parse()
	})
}
