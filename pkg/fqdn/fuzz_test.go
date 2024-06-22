// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzMapSelectorsToNamesLocked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		fqdnSelector := api.FQDNSelector{}
		ff.FuzzMap(fqdnSelector)
		nameManager := NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),
		})
		nameManager.mapSelectorsToNamesLocked(fqdnSelector)
	})
}
