// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPortRuleHTTPValidateHost(t *testing.T) {
	valid := PortRuleHTTP{Host: `^example\.com$`}
	require.NoError(t, valid.Validate())

	invalid := PortRuleHTTP{Host: "("}
	require.Error(t, invalid.Validate())
}
