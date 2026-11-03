// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/chart/common"
	"helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/engine"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

func TestResolveHelmChartVersion(t *testing.T) {
	type args struct {
		versionFlag        string
		chartDirectoryFlag string
	}
	tests := []struct {
		name    string
		args    args
		want    semver.Version
		wantErr bool
	}{
		{
			name:    "valid-version",
			args:    args{versionFlag: "v1.11.5", chartDirectoryFlag: ""},
			want:    semver.Version{Major: 1, Minor: 11, Patch: 5},
			wantErr: false,
		},
		{
			name:    "missing-version",
			args:    args{versionFlag: "v0.0.0", chartDirectoryFlag: ""},
			wantErr: true,
		},
		{
			name:    "invalid-version",
			args:    args{versionFlag: "random-version", chartDirectoryFlag: ""},
			wantErr: true,
		},
		{
			name:    "valid-chart-directory",
			args:    args{versionFlag: "", chartDirectoryFlag: "./testdata"},
			want:    semver.Version{Major: 1, Minor: 2, Patch: 3},
			wantErr: false,
		},
		{
			name:    "invalid-chart-directory",
			args:    args{versionFlag: "", chartDirectoryFlag: "/invalid/chart-directory"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := ResolveHelmChartVersion(tt.args.versionFlag, tt.args.chartDirectoryFlag, defaults.HelmRepository)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveHelmChartVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseVals(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    map[string]any
		wantErr bool
	}{
		{
			name:    "simple-val",
			input:   []string{"simple=true"},
			want:    map[string]any{"simple": true},
			wantErr: false,
		},
		{
			name:    "two-levels",
			input:   []string{"two.levels=true"},
			want:    map[string]any{"two": map[string]any{"levels": true}},
			wantErr: false,
		},
		{
			name:    "multiple-keys",
			input:   []string{"multiple=true", "keys=true"},
			want:    map[string]any{"multiple": true, "keys": true},
			wantErr: false,
		},
		{
			name:    "string-type",
			input:   []string{"string=testval"},
			want:    map[string]any{"string": "testval"},
			wantErr: false,
		},
		{
			name:    "mixed-type",
			input:   []string{"string=testval", "bool=false"},
			want:    map[string]any{"string": "testval", "bool": false},
			wantErr: false,
		},
		{
			name:  "mixed-levels",
			input: []string{"two.levels=true", "three.levels.deep=true"},
			want: map[string]any{
				"two":   map[string]any{"levels": true},
				"three": map[string]any{"levels": map[string]any{"deep": true}},
			},
			wantErr: false,
		},
		{
			name:    "invalid-input",
			input:   []string{"invalid"},
			wantErr: true,
		},
		{
			name:    "mixed-invalid",
			input:   []string{"testkey=val", "invalid"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVals(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetDefaultVersionString(t *testing.T) {
	versionString := GetDefaultVersionString()
	version, err := semver.ParseTolerant(versionString)
	assert.NoError(t, err)
	assert.Nil(t, version.Pre)
}

// Render the chart's bootstrap: the embedded Envoy bootstrap uses separate Go
// code, so its tests cannot catch Helm selecting a different EDS transport.
func TestEnvoyLocalityClusterXDSMode(t *testing.T) {
	chart, err := loader.LoadDir("../../../install/kubernetes/cilium")
	require.NoError(t, err)
	// Keep the production ConfigMap and shared helpers, without rendering
	// unrelated Kubernetes objects or generating their certificates.
	const configMapTemplate = "templates/cilium-envoy/configmap.yaml"
	templates := chart.Templates[:0]
	for _, template := range chart.Templates {
		if template.Name == configMapTemplate || strings.HasSuffix(template.Name, ".tpl") {
			templates = append(templates, template)
		}
	}
	chart.Templates = templates

	tests := []struct {
		name                 string
		mode                 string
		upgradeCompatibility string
		ads                  bool
		apiType              string
	}{
		{name: "default", ads: true, apiType: "GRPC"},
		{name: "ads", mode: "ads", ads: true, apiType: "GRPC"},
		{name: "strict-ads", mode: "strict-ads", ads: true, apiType: "GRPC"},
		{name: "delta-ads", mode: "delta-ads", ads: true, apiType: "DELTA_GRPC"},
		{name: "split", mode: "split", apiType: "GRPC"},
		{name: "delta-split", mode: "delta-split", apiType: "DELTA_GRPC"},
		{name: "upgrade compatibility", upgradeCompatibility: "1.19", apiType: "GRPC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envoy := map[string]any{
				"enabled":      true,
				"nodeLocality": map[string]any{"enabled": true},
			}
			if tt.mode != "" {
				envoy["xdsMode"] = tt.mode
			}
			values, err := util.ToRenderValues(chart, map[string]any{
				"envoy": envoy, "upgradeCompatibility": tt.upgradeCompatibility,
			}, common.ReleaseOptions{Name: "cilium", Namespace: "kube-system", IsInstall: true}, nil)
			require.NoError(t, err)
			rendered, err := engine.Render(chart, values)
			require.NoError(t, err)
			var configMap struct {
				Data map[string]string
			}
			require.NoError(t, yaml.Unmarshal([]byte(rendered["cilium/"+configMapTemplate]), &configMap))
			require.Contains(t, configMap.Data, "bootstrap-config.json")
			var bootstrap struct {
				StaticResources struct {
					Clusters []struct {
						Name             string
						EdsClusterConfig struct {
							EdsConfig map[string]any
						}
					}
				}
				DynamicResources map[string]any
			}
			require.NoError(t, json.Unmarshal([]byte(configMap.Data["bootstrap-config.json"]), &bootstrap))
			var edsConfig map[string]any
			for _, cluster := range bootstrap.StaticResources.Clusters {
				if cluster.Name == "/cilium-locality-cluster" {
					edsConfig = cluster.EdsClusterConfig.EdsConfig
				}
			}
			require.NotNil(t, edsConfig)
			require.Equal(t, "V3", edsConfig["resourceApiVersion"])
			if tt.ads {
				require.Contains(t, edsConfig, "ads", "the locality cluster must use the same ADS stream as LDS and CDS")
				require.NotContains(t, edsConfig, "apiConfigSource")
				require.Equal(t, tt.apiType, bootstrap.DynamicResources["adsConfig"].(map[string]any)["apiType"])
			} else {
				require.NotContains(t, edsConfig, "ads")
				require.NotContains(t, bootstrap.DynamicResources, "adsConfig")
				require.Equal(t, tt.apiType, edsConfig["apiConfigSource"].(map[string]any)["apiType"])
			}
		})
	}
}
