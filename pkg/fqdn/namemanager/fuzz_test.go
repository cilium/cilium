// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzMapSelectorsToNamesLocked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		fqdnSelector := api.FQDNSelector{}
		ff.FuzzMap(fqdnSelector)
		nameManager := New(fqdn.Config{
			MinTTL: 1,
			Cache:  fqdn.NewDNSCache(0),
		})
		nameManager.mapSelectorsToNamesLocked(fqdnSelector)
	})
}
