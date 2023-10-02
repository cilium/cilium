// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestFeatureSetMatchRequirements(t *testing.T) {
	features := Set{}
	matches, _ := features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches, _ = features.MatchRequirements(RequireEnabled(L7Proxy))
	if matches {
		t.Error("empty features should not match any requirement")
	}

	features[L7Proxy] = Status{
		Enabled: true,
	}
	matches, _ = features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches, _ = features.MatchRequirements(RequireEnabled(L7Proxy))
	if !matches {
		t.Errorf("expected features %v to match feature %v", features, L7Proxy)
	}

	cniMode := "aws-cni"
	features[CNIChaining] = Status{
		Enabled: true,
		Mode:    cniMode,
	}
	matches, _ = features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches, _ = features.MatchRequirements(RequireEnabled(L7Proxy))
	if !matches {
		t.Errorf("expected features %v to match feature %v", features, L7Proxy)
	}
	matches, _ = features.MatchRequirements(RequireEnabled(CNIChaining), RequireMode(CNIChaining, cniMode))
	if !matches {
		t.Errorf("expected features %v to match feature %v with mode %v", features, CNIChaining, cniMode)
	}
	cniMode = "generic-veth"
	matches, _ = features.MatchRequirements(RequireEnabled(CNIChaining), RequireMode(CNIChaining, cniMode))
	if matches {
		t.Errorf("features %v unexpectedly matched feature %v with mode %v", features, CNIChaining, cniMode)
	}
}

func TestFeatureSet_extractFeaturesFromConfigMap(t *testing.T) {
	fs := Set{}
	ciliumVersion := semver.Version{Major: 1, Minor: 14, Patch: 0}
	cm := corev1.ConfigMap{}
	fs.ExtractFromConfigMap(ciliumVersion, &cm)
	cm.Data = map[string]string{
		"enable-ipv4":                "true",
		"enable-ipv6":                "true",
		"routing-mode":               "tunnel",
		"tunnel-protocol":            "geneve",
		"mesh-auth-mutual-enabled":   "true",
		"enable-ipv4-egress-gateway": "true",
	}
	fs.ExtractFromConfigMap(ciliumVersion, &cm)
	assert.True(t, fs[IPv4].Enabled)
	assert.True(t, fs[IPv6].Enabled)
	assert.True(t, fs[AuthSpiffe].Enabled)
	assert.True(t, fs[EgressGateway].Enabled)
	assert.True(t, fs[Tunnel].Enabled)
	assert.Equal(t, "geneve", fs[Tunnel].Mode)
}
