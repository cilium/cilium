// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/hive"
)

func TestStandaloneDNSProxy(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
	)

	err := hive.New(StandaloneDNSProxyCell).Populate(hivetest.Logger(t))
	assert.NoError(t, err, "Populate()")
}
