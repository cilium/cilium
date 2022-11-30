// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maglev

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func FuzzGetLookupTable(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, m uint64) {
		backendsMap := make(map[string]*loadbalancer.Backend)
		ff := fuzz.NewConsumer(data)
		ff.FuzzMap(&backendsMap)
		_ = GetLookupTable(backendsMap, m)
	})
}
