// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitCloudProviderPolicy(t *testing.T) {
	t.Run("empty deny-tuples", func(t *testing.T) {
		_, err := initCloudProviderPolicy("")
		assert.NotNil(t, err)
		assert.ErrorContains(t, err, "Invalid egress-deny-tuples input")
	})

	t.Run("Invalid input with wrong format", func(t *testing.T) {
		_, err := initCloudProviderPolicy("1.1.1.1;")
		assert.NotNil(t, err)
		assert.ErrorContains(t, err, "Invalid egress-deny-tuples input")
	})

	t.Run("Empty Ip, port and protocol", func(t *testing.T) {
		rules, err := initCloudProviderPolicy(";;")
		assert.Nil(t, err)
		assert.Equal(t, 1, len(rules))
		egDenyRules := rules[0].EgressDeny
		assert.Equal(t, 1, len(egDenyRules))
		assert.Equal(t, 0, len(egDenyRules[0].ToCIDR))
		assert.Equal(t, 1, len(egDenyRules))
		assert.Equal(t, 0, len(egDenyRules[0].ToPorts))
	})

	t.Run("Egress deny only on ip address", func(t *testing.T) {
		rules, err := initCloudProviderPolicy("1.1.1.1;;")
		assert.Nil(t, err)
		assert.Equal(t, 1, len(rules))
		egDenyRules := rules[0].EgressDeny
		assert.Equal(t, 1, len(egDenyRules))
		assert.Equal(t, 1, len(egDenyRules[0].ToCIDR))
		assert.Equal(t, "1.1.1.1", string(egDenyRules[0].ToCIDR[0]))
		assert.Equal(t, 0, len(egDenyRules[0].ToPorts))
	})

	t.Run("Egress deny only on ip address and port", func(t *testing.T) {
		rules, err := initCloudProviderPolicy("1.1.1.1;80;")
		assert.Nil(t, err)
		assert.Equal(t, 1, len(rules))
		egDenyRules := rules[0].EgressDeny
		assert.Equal(t, 1, len(egDenyRules))
		assert.Equal(t, 1, len(egDenyRules[0].ToCIDR))
		assert.Equal(t, "1.1.1.1", string(egDenyRules[0].ToCIDR[0]))
		assert.Equal(t, 1, len(egDenyRules[0].ToPorts))
		assert.Equal(t, "80", string(egDenyRules[0].ToPorts[0].Ports[0].Port))
		assert.Equal(t, "", string(egDenyRules[0].ToPorts[0].Ports[0].Protocol))
	})

	t.Run("Egress deny ip address, port and protocol", func(t *testing.T) {
		rules, err := initCloudProviderPolicy("1.1.1.1;80;tcp")
		assert.Nil(t, err)
		assert.Equal(t, 1, len(rules))
		egDenyRules := rules[0].EgressDeny
		assert.Equal(t, 1, len(egDenyRules))
		assert.Equal(t, 1, len(egDenyRules[0].ToCIDR))
		assert.Equal(t, "1.1.1.1", string(egDenyRules[0].ToCIDR[0]))
		assert.Equal(t, 1, len(egDenyRules[0].ToPorts))
		assert.Equal(t, "80", string(egDenyRules[0].ToPorts[0].Ports[0].Port))
		assert.Equal(t, "TCP", string(egDenyRules[0].ToPorts[0].Ports[0].Protocol))
	})
}
