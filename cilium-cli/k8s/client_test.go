package k8s

import "testing"

func TestGetCiliumVersionFromImage(t *testing.T) {
	tests := []struct {
		name            string
		image           string
		expectedVersion string
	}{
		{"registry name and tag", "quay.io/cilium/cilium:latest", "latest"},
		{"registry name and tag with digest", "quay.io/cilium/cilium:latest@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2", "latest"},
		{"no registry name and tag", "cilium/cilium:latest", "latest"},
		{"no registry name and tag with digest", "cilium/cilium:latest@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2", "latest"},
		{"no tag", "quay.io/cilium/cilium", "latest"},
		{"with hyphen", "quay.io/cilium/cilium-ci", "-ci:latest"},
		{"with hyphen and hash", "quay.io/cilium/cilium-ci:93f68432e8da3adf8b74972b3aa6a53fc2c36517", "-ci:93f68432e8da3adf8b74972b3aa6a53fc2c36517"},
		{"with hypen, dash and digest", "quay.io/cilium/cilium-ci:93f68432e8da3adf8b74972b3aa6a53fc2c36517@sha256:f2b7707b0b5130ccc2d3fa493a9262d5989ee2eacd712b1c5136391a8361a830", "-ci:93f68432e8da3adf8b74972b3aa6a53fc2c36517"},
		{"registry with port number", "localhost:5000/cilium/cilium:latest", "latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := getCiliumVersionFromImage(tt.image)
			if err != nil {
				t.Errorf("got an unexpected error: %s", err.Error())
			}

			if version != tt.expectedVersion {
				t.Errorf("expect version %s, got %s", version, tt.expectedVersion)
			}
		})
	}
}
