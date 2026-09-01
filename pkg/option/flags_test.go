// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
)

func TestRegisterCommonPolicyFlags(t *testing.T) {
	vp := viper.New()
	flags := pflag.NewFlagSet("policy-validation", pflag.ContinueOnError)
	RegisterCommonPolicyFlags(vp, flags)
	require.NoError(t, vp.BindPFlags(flags))

	require.Equal(t, defaults.EnableL7Proxy, vp.GetBool(EnableL7Proxy))
	require.Equal(t, defaults.EnableICMPRules, vp.GetBool(EnableICMPRules))
	require.Equal(t, defaults.EnableNodeSelectorLabels, vp.GetBool(EnableNodeSelectorLabels))
	require.Equal(t, defaults.EnableNonDefaultDenyPolicies, vp.GetBool(EnableNonDefaultDenyPolicies))
	require.Equal(t, defaults.EnableExtendedIPProtocols, vp.GetBool(EnableExtendedIPProtocols))

	vp.Set(EnableL7Proxy, "false")
	vp.Set(EnableICMPRules, "false")
	vp.Set(EnableNodeSelectorLabels, "true")
	vp.Set(EnableNonDefaultDenyPolicies, "false")
	vp.Set(EnableExtendedIPProtocols, "true")
	require.False(t, vp.GetBool(EnableL7Proxy))
	require.False(t, vp.GetBool(EnableICMPRules))
	require.True(t, vp.GetBool(EnableNodeSelectorLabels))
	require.False(t, vp.GetBool(EnableNonDefaultDenyPolicies))
	require.True(t, vp.GetBool(EnableExtendedIPProtocols))
}
