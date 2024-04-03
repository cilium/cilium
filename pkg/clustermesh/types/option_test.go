// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
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
		wantMCCErr    bool
		wantErr       bool
		wantStrictErr bool
	}{
		{
			cinfo:         ClusterInfo{ID: 0, Name: "default", MaxConnectedClusters: 255},
			wantErr:       false,
			wantStrictErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 0, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       false,
			wantStrictErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 1, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       false,
			wantStrictErr: false,
		},
		{
			cinfo:         ClusterInfo{ID: 255, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       false,
			wantStrictErr: false,
		},
		{
			cinfo:         ClusterInfo{ID: 75, Name: "default", MaxConnectedClusters: 255},
			wantErr:       true,
			wantStrictErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 256, Name: "foo", MaxConnectedClusters: 255},
			wantErr:       true,
			wantStrictErr: true,
		},
		{
			cinfo:         ClusterInfo{ID: 1, Name: "foo", MaxConnectedClusters: 512},
			wantMCCErr:    true,
			wantErr:       false,
			wantStrictErr: false,
		},
		{
			cinfo:         ClusterInfo{ID: 512, Name: "foo", MaxConnectedClusters: 511},
			wantErr:       true,
			wantStrictErr: true,
		},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("ID: %d, Name: %s, MaxConnectedClusters: %d", tt.cinfo.ID, tt.cinfo.Name, tt.cinfo.MaxConnectedClusters)
		t.Run(name, func(t *testing.T) {
			if tt.wantMCCErr {
				assert.Error(t, tt.cinfo.InitClusterIDMax())
			} else {
				assert.NoError(t, tt.cinfo.InitClusterIDMax())
			}

			if tt.wantErr {
				assert.Error(t, tt.cinfo.Validate())
			} else {
				assert.NoError(t, tt.cinfo.Validate())
			}

			if tt.wantStrictErr {
				assert.Error(t, tt.cinfo.ValidateStrict())
			} else {
				assert.NoError(t, tt.cinfo.ValidateStrict())
			}
		})
	}
}

func TestValidateRemoteConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *CiliumClusterConfig
		mcc       uint32
		mode      ValidationMode
		assertion func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
	}{
		{
			name:      "Nil config (Backward)",
			cfg:       nil,
			mcc:       255,
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Nil config (Strict)",
			cfg:       nil,
			mcc:       255,
			mode:      Strict,
			assertion: assert.Error,
		},
		{
			name:      "Empty config (Backward)",
			cfg:       &CiliumClusterConfig{},
			mcc:       255,
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Empty config (Strict)",
			cfg:       &CiliumClusterConfig{},
			mcc:       255,
			mode:      Strict,
			assertion: assert.Error,
		},
		{
			name:      "Valid config (Backward)",
			cfg:       &CiliumClusterConfig{ID: 255},
			mcc:       255,
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Valid config (Strict)",
			cfg:       &CiliumClusterConfig{ID: 255, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 255}},
			mcc:       255,
			mode:      Strict,
			assertion: assert.NoError,
		},
		{
			name:      "Invalid config (Backward)",
			cfg:       &CiliumClusterConfig{ID: 256},
			mcc:       255,
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
		{
			name:      "Invalid config (Strict)",
			cfg:       &CiliumClusterConfig{ID: 256},
			mcc:       255,
			mode:      Strict,
			assertion: assert.Error,
		},
		// Extended ClusterMesh requires CiliumClusterConfig, so use
		// BackwardCompatible mode for these tests (most permissive)
		{
			name:      "Nil config (ClusterMesh511)",
			cfg:       nil,
			mcc:       511,
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
		{
			name:      "Empty config (ClusterMesh511)",
			cfg:       &CiliumClusterConfig{},
			mcc:       511,
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
		{
			name:      "Invalid config, MaxConnectedClusters mistmatch (ClusterMesh255)",
			cfg:       &CiliumClusterConfig{ID: 511, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 511}},
			mcc:       255,
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
		{
			name:      "Valid config (ClusterMesh511)",
			cfg:       &CiliumClusterConfig{ID: 511, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 511}},
			mcc:       511,
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Invalid config, MaxConnectedClusters mistmatch (ClusterMesh511)",
			cfg:       &CiliumClusterConfig{ID: 511, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 255}},
			mcc:       511,
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
		{
			name:      "Invalid config (ClusterMesh511)",
			cfg:       &CiliumClusterConfig{ID: 512, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 511}},
			mcc:       511,
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cinfo := ClusterInfo{MaxConnectedClusters: tt.mcc}
			// ClusterIDMax needs to be initialized here. This is ordinarily
			// executed during agent intialization.
			cinfo.InitClusterIDMax()
			tt.assertion(t, cinfo.ValidateRemoteConfig(bool(tt.mode), tt.cfg))
		})
	}
}
