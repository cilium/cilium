// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"log/slog"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func FuzzCiliumNetworkPolicyParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		r := &ciliumv2.CiliumNetworkPolicy{}
		ff.GenerateStruct(r)
		clusterName, _ := ff.GetString()
		_, _ = ParseCiliumNetworkPolicy(slog.New(slog.DiscardHandler), clusterName, r)
	})
}
