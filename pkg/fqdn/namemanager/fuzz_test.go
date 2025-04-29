// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzMapSelectorsToNamesLocked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		fqdnSelector := api.FQDNSelector{}
		ff.FuzzMap(fqdnSelector)
		nameManager := New(ManagerParams{
			Logger: hivetest.Logger(f),
			Config: NameManagerConfig{
				MinTTL:            1,
				DNSProxyLockCount: defaults.DNSProxyLockCount,
				StateDir:          defaults.StateDir,
			},
		})
		nameManager.mapSelectorsToNamesLocked(fqdnSelector)
	})
}
