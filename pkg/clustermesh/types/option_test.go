// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
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
		{
			cinfo:         ClusterInfo{ID: 10, Name: "invAlid", MaxConnectedClusters: 511},
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

func TestClusterInfoValidateBuggyClusterID(t *testing.T) {
	tests := []struct {
		cinfo        ClusterInfo
		ipamMode     string
		chainingMode string
		assert       assert.ErrorAssertionFunc
	}{
		{cinfo: ClusterInfo{ID: 127}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 128}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 255}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 256}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 127}, ipamMode: ipamOption.IPAMENI, assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 128}, ipamMode: ipamOption.IPAMENI, assert: assert.Error},
		{cinfo: ClusterInfo{ID: 255}, ipamMode: ipamOption.IPAMAlibabaCloud, assert: assert.Error},
		{cinfo: ClusterInfo{ID: 256}, ipamMode: ipamOption.IPAMAlibabaCloud, assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 127}, chainingMode: "aws-cni", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 128}, chainingMode: "aws-cni", assert: assert.Error},
		{cinfo: ClusterInfo{ID: 255}, chainingMode: "aws-cni", assert: assert.Error},
		{cinfo: ClusterInfo{ID: 256}, chainingMode: "aws-cni", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 383}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 384}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 511}, ipamMode: ipamOption.IPAMClusterPool, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 383}, ipamMode: ipamOption.IPAMENI, chainingMode: "foo", assert: assert.NoError},
		{cinfo: ClusterInfo{ID: 384}, ipamMode: ipamOption.IPAMENI, chainingMode: "foo", assert: assert.Error},
		{cinfo: ClusterInfo{ID: 511}, ipamMode: ipamOption.IPAMAlibabaCloud, chainingMode: "foo", assert: assert.Error},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("ID: %d, IPAM: %s, Chaining: %s", tt.cinfo.ID, tt.ipamMode, tt.chainingMode)
		t.Run(name, func(t *testing.T) {
			tt.assert(t, tt.cinfo.ValidateBuggyClusterID(tt.ipamMode, tt.chainingMode))
		})
	}
}

func TestValidateRemoteConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       CiliumClusterConfig
		mcc       uint32
		assertion func(t assert.TestingT, err error, msgAndArgs ...any) bool
	}{
		{
			name:      "Empty config",
			cfg:       CiliumClusterConfig{},
			mcc:       255,
			assertion: assert.Error,
		},
		{
			name:      "Valid config",
			cfg:       CiliumClusterConfig{ID: 255, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 255}},
			mcc:       255,
			assertion: assert.NoError,
		},
		{
			name:      "Invalid config",
			cfg:       CiliumClusterConfig{ID: 256},
			mcc:       255,
			assertion: assert.Error,
		},
		{
			name:      "Invalid config, MaxConnectedClusters mismatch (ClusterMesh255)",
			cfg:       CiliumClusterConfig{ID: 511, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 511}},
			mcc:       255,
			assertion: assert.Error,
		},
		{
			name:      "Valid config (ClusterMesh511)",
			cfg:       CiliumClusterConfig{ID: 511, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 511}},
			mcc:       511,
			assertion: assert.NoError,
		},
		{
			name:      "Invalid config, MaxConnectedClusters mismatch (ClusterMesh511)",
			cfg:       CiliumClusterConfig{ID: 511, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 255}},
			mcc:       511,
			assertion: assert.Error,
		},
		{
			name:      "Invalid config (ClusterMesh511)",
			cfg:       CiliumClusterConfig{ID: 512, Capabilities: CiliumClusterConfigCapabilities{MaxConnectedClusters: 511}},
			mcc:       511,
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cinfo := ClusterInfo{MaxConnectedClusters: tt.mcc}
			// ClusterIDMax needs to be initialized here. This is ordinarily
			// executed during agent initialization.
			cinfo.InitClusterIDMax()
			tt.assertion(t, cinfo.ValidateRemoteConfig(tt.cfg))
		})
	}
}
