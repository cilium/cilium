// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"testing"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func TestWithCrossClusterOnly(t *testing.T) {
	podScenario := PodToPod(WithCrossClusterOnly()).(*podToPod)
	if !podScenario.crossClusterOnly {
		t.Fatal("PodToPod did not enable cross-cluster filtering")
	}

	endpointScenario := PodToPodWithEndpoints(WithCrossClusterOnly()).(*podToPodWithEndpoints)
	if !endpointScenario.crossClusterOnly {
		t.Fatal("PodToPodWithEndpoints did not enable cross-cluster filtering")
	}
}

func TestPodToPodActionName(t *testing.T) {
	got := podToPodActionName(features.IPFamilyV4, 2)
	if want := "curl-ipv4-2"; got != want {
		t.Fatalf("podToPodActionName() = %q, want %q", got, want)
	}
}

func TestPodToPodCrossClusterActionName(t *testing.T) {
	got := podToPodCrossClusterActionName(features.IPFamilyV4, 2, "cluster-a", "cluster-b")
	if want := "curl-ipv4-cluster-a-to-cluster-b-2"; got != want {
		t.Fatalf("podToPodCrossClusterActionName() = %q, want %q", got, want)
	}
}
