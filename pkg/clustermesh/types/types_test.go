// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClusterNameValidate(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		check       assert.ErrorAssertionFunc
	}{
		{
			name:        "empty",
			clusterName: "",
			check:       assert.Error,
		},
		{
			name:        "single character",
			clusterName: "a",
			check:       assert.NoError,
		},
		{
			name:        "32 characters",
			clusterName: "abcdefghijklmnopqrstuvwxyz-01234",
			check:       assert.NoError,
		},
		{
			name:        "33 characters",
			clusterName: "abcdefghijklmnopqrstuvwxyz-012345",
			check:       assert.Error,
		},
		{
			name:        "start and end with lowercase letter",
			clusterName: "az",
			check:       assert.NoError,
		},
		{
			name:        "start and end with number",
			clusterName: "09",
			check:       assert.NoError,
		},
		{
			name:        "start with a dash",
			clusterName: "-a",
			check:       assert.Error,
		},
		{
			name:        "end with a dash",
			clusterName: "0-",
			check:       assert.Error,
		},
		{
			name:        "uppercase letters",
			clusterName: "aBYz",
			check:       assert.Error,
		},
		{
			name:        "invalid characters",
			clusterName: "a^x",
			check:       assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, ValidateClusterName(tt.clusterName))
		})
	}
}

func TestClusterInfoNumericIdentityLayout(t *testing.T) {
	tests := []struct {
		name                    string
		cinfo                   ClusterInfo
		expectedClusterIDBits   uint32
		expectedClusterIDShift  uint32
		expectedMinimalIdentity uint32
		expectedMaximumIdentity uint32
	}{
		{
			name: "cluster-id-0-max-255",
			cinfo: ClusterInfo{
				ID:                   0,
				MaxConnectedClusters: 255,
			},
			expectedClusterIDBits:   8,
			expectedClusterIDShift:  16,
			expectedMinimalIdentity: 0x000100,
			expectedMaximumIdentity: 0x00FFFF,
		},
		{
			name: "cluster-id-1-max-255",
			cinfo: ClusterInfo{
				ID:                   1,
				MaxConnectedClusters: 255,
			},
			expectedClusterIDBits:   8,
			expectedClusterIDShift:  16,
			expectedMinimalIdentity: 0x010000,
			expectedMaximumIdentity: 0x01FFFF,
		},
		{
			name: "cluster-id-255-max-255",
			cinfo: ClusterInfo{
				ID:                   255,
				MaxConnectedClusters: 255,
			},
			expectedClusterIDBits:   8,
			expectedClusterIDShift:  16,
			expectedMinimalIdentity: 0xFF0000,
			expectedMaximumIdentity: 0xFFFFFF,
		},
		{
			name: "cluster-id-0-max-511",
			cinfo: ClusterInfo{
				ID:                   0,
				MaxConnectedClusters: 511,
			},
			expectedClusterIDBits:   9,
			expectedClusterIDShift:  15,
			expectedMinimalIdentity: 0x000100,
			expectedMaximumIdentity: 0x007FFF,
		},
		{
			name: "cluster-id-1-max-511",
			cinfo: ClusterInfo{
				ID:                   1,
				MaxConnectedClusters: 511,
			},
			expectedClusterIDBits:   9,
			expectedClusterIDShift:  15,
			expectedMinimalIdentity: 0x008000,
			expectedMaximumIdentity: 0x00FFFF,
		},
		{
			name: "cluster-id-511-max-511",
			cinfo: ClusterInfo{
				ID:                   511,
				MaxConnectedClusters: 511,
			},
			expectedClusterIDBits:   9,
			expectedClusterIDShift:  15,
			expectedMinimalIdentity: 0xFF8000,
			expectedMaximumIdentity: 0xFFFFFF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedClusterIDBits, tt.cinfo.GetClusterIDBits())
			assert.Equal(t, tt.expectedClusterIDShift, tt.cinfo.GetClusterIDShift())
			assert.Equal(t, tt.expectedMinimalIdentity, tt.cinfo.MinimalAllocationIdentity())
			assert.Equal(t, tt.expectedMaximumIdentity, tt.cinfo.MaximumAllocationIdentity())
			assert.Equal(t, tt.expectedMinimalIdentity, tt.cinfo.MinimalAllocationIdentityFor(tt.cinfo.ID))
			assert.Equal(t, tt.expectedMaximumIdentity, tt.cinfo.MaximumAllocationIdentityFor(tt.cinfo.ID))
		})
	}
}

func TestClusterInfoAllocationIdentityFor(t *testing.T) {
	tests := []struct {
		name                    string
		cinfo                   ClusterInfo
		clusterID               uint32
		expectedMinimalIdentity uint32
		expectedMaximumIdentity uint32
	}{
		{
			name:                    "255-cluster-layout",
			cinfo:                   ClusterInfo{ID: 42, MaxConnectedClusters: 255},
			clusterID:               1,
			expectedMinimalIdentity: 0x010000,
			expectedMaximumIdentity: 0x01FFFF,
		},
		{
			name:                    "511-cluster-layout",
			cinfo:                   ClusterInfo{ID: 42, MaxConnectedClusters: 511},
			clusterID:               1,
			expectedMinimalIdentity: 0x008000,
			expectedMaximumIdentity: 0x00FFFF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedMinimalIdentity, tt.cinfo.MinimalAllocationIdentityFor(tt.clusterID))
			assert.Equal(t, tt.expectedMaximumIdentity, tt.cinfo.MaximumAllocationIdentityFor(tt.clusterID))
		})
	}
}
