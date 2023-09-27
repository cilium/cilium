// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestFeatureSetMatchRequirements(t *testing.T) {
	features := FeatureSet{}
	matches, _ := features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches, _ = features.MatchRequirements(RequireFeatureEnabled(FeatureL7Proxy))
	if matches {
		t.Error("empty features should not match any requirement")
	}

	features[FeatureL7Proxy] = FeatureStatus{
		Enabled: true,
	}
	matches, _ = features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches, _ = features.MatchRequirements(RequireFeatureEnabled(FeatureL7Proxy))
	if !matches {
		t.Errorf("expected features %v to match feature %v", features, FeatureL7Proxy)
	}

	cniMode := "aws-cni"
	features[FeatureCNIChaining] = FeatureStatus{
		Enabled: true,
		Mode:    cniMode,
	}
	matches, _ = features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches, _ = features.MatchRequirements(RequireFeatureEnabled(FeatureL7Proxy))
	if !matches {
		t.Errorf("expected features %v to match feature %v", features, FeatureL7Proxy)
	}
	matches, _ = features.MatchRequirements(RequireFeatureEnabled(FeatureCNIChaining), RequireFeatureMode(FeatureCNIChaining, cniMode))
	if !matches {
		t.Errorf("expected features %v to match feature %v with mode %v", features, FeatureCNIChaining, cniMode)
	}
	cniMode = "generic-veth"
	matches, _ = features.MatchRequirements(RequireFeatureEnabled(FeatureCNIChaining), RequireFeatureMode(FeatureCNIChaining, cniMode))
	if matches {
		t.Errorf("features %v unexpectedly matched feature %v with mode %v", features, FeatureCNIChaining, cniMode)
	}
}

func TestFeatureSet_extractFeaturesFromConfigMap(t *testing.T) {
	fs := FeatureSet{}
	ciliumVersion := semver.Version{Major: 1, Minor: 14, Patch: 0}
	cm := corev1.ConfigMap{}
	fs.extractFeaturesFromConfigMap(ciliumVersion, &cm)
	cm.Data = map[string]string{
		"enable-ipv4":                "true",
		"enable-ipv6":                "true",
		"routing-mode":               "tunnel",
		"tunnel-protocol":            "geneve",
		"mesh-auth-mutual-enabled":   "true",
		"enable-ipv4-egress-gateway": "true",
	}
	fs.extractFeaturesFromConfigMap(ciliumVersion, &cm)
	assert.True(t, fs[FeatureIPv4].Enabled)
	assert.True(t, fs[FeatureIPv6].Enabled)
	assert.True(t, fs[FeatureAuthSpiffe].Enabled)
	assert.True(t, fs[FeatureEgressGateway].Enabled)
	assert.True(t, fs[FeatureTunnel].Enabled)
	assert.Equal(t, "geneve", fs[FeatureTunnel].Mode)
}
