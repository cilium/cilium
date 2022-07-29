// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

package check

import "testing"

func TestFeatureSetMatchRequirements(t *testing.T) {
	features := FeatureSet{}
	matches := features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches = features.MatchRequirements(RequireFeatureEnabled(FeatureL7Proxy))
	if matches {
		t.Error("empty features should not match any requirement")
	}

	features[FeatureL7Proxy] = FeatureStatus{
		Enabled: true,
	}
	matches = features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches = features.MatchRequirements(RequireFeatureEnabled(FeatureL7Proxy))
	if !matches {
		t.Errorf("expected features %v to match feature %v", features, FeatureL7Proxy)
	}

	cniMode := "aws-cni"
	features[FeatureCNIChaining] = FeatureStatus{
		Enabled: true,
		Mode:    cniMode,
	}
	matches = features.MatchRequirements()
	if !matches {
		t.Error("empty requirements should always match")
	}
	matches = features.MatchRequirements(RequireFeatureEnabled(FeatureL7Proxy))
	if !matches {
		t.Errorf("expected features %v to match feature %v", features, FeatureL7Proxy)
	}
	matches = features.MatchRequirements(RequireFeatureEnabled(FeatureCNIChaining), RequireFeatureMode(FeatureCNIChaining, cniMode))
	if !matches {
		t.Errorf("expected features %v to match feature %v with mode %v", features, FeatureCNIChaining, cniMode)
	}
	cniMode = "generic-veth"
	matches = features.MatchRequirements(RequireFeatureEnabled(FeatureCNIChaining), RequireFeatureMode(FeatureCNIChaining, cniMode))
	if matches {
		t.Errorf("features %v unexpectedly matched feature %v with mode %v", features, FeatureCNIChaining, cniMode)
	}
}
