// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClusterInfoValidate(t *testing.T) {
	// this test involves changing the global ClusterIDMax variable, so we need
	// to save its value and restore it at the end of the test
	oldMaxClusterID := ClusterIDMax
	defer func() { ClusterIDMax = oldMaxClusterID }()

	tests := []struct {
		cinfo         ClusterInfo
		wantErr       bool
		strictWantErr bool
	}{
		{
			cinfo:         ClusterInfo{ID: 0, Name: "default", MaxConnectedClusters: 255},
			wantErr:       false,
			strictWantErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 0, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       false,
			strictWantErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 1, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       false,
			strictWantErr: false,
		},
		{
			cinfo:         ClusterInfo{ID: 255, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       false,
			strictWantErr: false,
		},
		{
			cinfo:         ClusterInfo{ID: 75, Name: "default", MaxConnectedClusters: 255},
			wantErr:       true,
			strictWantErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 256, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       true,
			strictWantErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 1, Name: "foo", MaxConnectedClusters: 512},
			wantErr:       true,
			strictWantErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 512, Name: "foo", MaxConnectedClusters: 511},
			wantErr:       true,
			strictWantErr: true,
		},
	}

	for _, tt := range tests {
		if tt.wantErr {
			assert.Error(t, tt.cinfo.Validate())
		} else {
			assert.NoError(t, tt.cinfo.Validate())
		}

		if tt.strictWantErr {
			assert.Error(t, tt.cinfo.ValidateStrict())
		} else {
			assert.NoError(t, tt.cinfo.ValidateStrict())
		}
	}
}
