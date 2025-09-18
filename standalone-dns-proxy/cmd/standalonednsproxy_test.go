// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestStandaloneDNSProxy(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	// Enable L7 proxy for the standalone DNS proxy
	option.Config.EnableL7Proxy = true
	h := hive.New(StandaloneDNSProxyCell)

	hive.AddConfigOverride(
		h,
		func(cfg *service.FQDNConfig) {
			cfg.EnableStandaloneDNSProxy = true
		})

	err := h.Populate(hivetest.Logger(t))
	assert.NoError(t, err, "Populate()")
}
