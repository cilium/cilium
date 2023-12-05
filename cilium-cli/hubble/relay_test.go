// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"strconv"
	"testing"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
)

func TestK8sHubbleRelayImage(t *testing.T) {
	tests := []struct {
		ciliumVersion string
		relayImage    string
		relayVersion  string
		want          string
	}{
		{
			ciliumVersion: "-cluster-mesh:v1.11.0-beta.1",
			relayImage:    "",
			relayVersion:  "",
			want:          "quay.io/cilium/hubble-relay-cluster-mesh:v1.11.0-beta.1",
		},
		{
			ciliumVersion: "v1.11.1",
			relayImage:    "",
			relayVersion:  "-cluster-mesh:v1.11.0-beta.1",
			want:          "quay.io/cilium/hubble-relay-cluster-mesh:v1.11.0-beta.1",
		},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			k := &K8sHubble{
				params: Parameters{
					RelayImage:   tt.relayImage,
					RelayVersion: tt.relayVersion,
				},
			}
			if got := k.relayImage(tt.ciliumVersion); got != tt.want {
				t.Errorf("k.relayImage(%s) == %q, want %q", tt.ciliumVersion, got, tt.want)
			}
		})
	}
}

func (k *K8sHubble) relayImage(ciliumVersion string) string {
	return utils.BuildImagePath(k.params.RelayImage, k.params.RelayVersion, defaults.RelayImage, ciliumVersion)
}
