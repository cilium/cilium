// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cilium/hive/hivetest"
)

func FuzzCiliumNetworkPolicyParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		r := &CiliumNetworkPolicy{}
		ff.GenerateStruct(r)
		clusterName, _ := ff.GetString()
		_, _ = r.Parse(hivetest.Logger(t), clusterName)
	})
}

func FuzzCiliumClusterwideNetworkPolicyParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		r := &CiliumClusterwideNetworkPolicy{}
		ff.GenerateStruct(r)
		clusterName, _ := ff.GetString()
		_, _ = r.Parse(hivetest.Logger(t), clusterName)
	})
}
