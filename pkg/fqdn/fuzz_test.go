// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzMapSelectorsToIPsLocked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		fqdnSelectors := make(sets.Set[api.FQDNSelector])
		ff.FuzzMap(&fqdnSelectors)
		if len(fqdnSelectors) == 0 {
			t.Skip()
		}
		nameManager := NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),
		})
		_, _ = nameManager.MapSelectorsToIPsLocked(fqdnSelectors)
	})
}
