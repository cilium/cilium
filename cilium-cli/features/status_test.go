// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
)

func Test_printPerNodeFeatureStatus(t *testing.T) {
	type args struct {
		nodeMap        perNodeMetrics
		sp             func(w io.Writer) statusPrinter
		buffer         bytes.Buffer
		expectedResult string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test tab writter output",
			args: args{
				nodeMap: perNodeMetrics{
					"node-1": {
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv4-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 1,
						},
						&models.Metric{
							Name:  "cilium_feature_adv_connect_and_lb_envoy_proxy_enabled",
							Value: 1,
						},
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv6-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 0,
						},
					},
					"node-2": {
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv4-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 1,
						},
						&models.Metric{
							Name:  "cilium_feature_adv_connect_and_lb_envoy_proxy_enabled",
							Value: 0,
						},
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv6-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 0,
						},
					},
					"node-3": {
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv4-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 1,
						},
						&models.Metric{
							Name:  "cilium_feature_adv_connect_and_lb_envoy_proxy_enabled",
							Value: 0,
						},
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv6-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 0,
						},
					},
				},
				sp:     func(w io.Writer) statusPrinter { return newTabWriter(w) },
				buffer: bytes.Buffer{},
				expectedResult: `Uniform  Name                                                   Labels              node-1  node-2  node-3  
Yes      cilium_feature_adv_connect_and_lb_big_tcp_enabled      protocol=ipv4-only  1       1       1       
Yes                                                             protocol=ipv6-only  0       0       0       
No       cilium_feature_adv_connect_and_lb_envoy_proxy_enabled                      1       0       0       
`,
			},
			wantErr: false,
		},
		{
			name: "Test markdown writer output",
			args: args{
				nodeMap: perNodeMetrics{
					"node-1": {
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv4-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 1,
						},
						&models.Metric{
							Name:  "cilium_feature_adv_connect_and_lb_envoy_proxy_enabled",
							Value: 1,
						},
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv6-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 0,
						},
					},
					"node-2": {
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv4-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 1,
						},
						&models.Metric{
							Name:  "cilium_feature_adv_connect_and_lb_envoy_proxy_enabled",
							Value: 0,
						},
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv6-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 0,
						},
					},
					"node-3": {
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv4-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 1,
						},
						&models.Metric{
							Name:  "cilium_feature_adv_connect_and_lb_envoy_proxy_enabled",
							Value: 0,
						},
						&models.Metric{
							Labels: map[string]string{
								"protocol": "ipv6-only",
							},
							Name:  "cilium_feature_adv_connect_and_lb_big_tcp_enabled",
							Value: 0,
						},
					},
				},
				sp:     func(w io.Writer) statusPrinter { return newMarkdownWriter(w) },
				buffer: bytes.Buffer{},
				expectedResult: `| Uniform | Name | Labels | node-1 | node-2 | node-3 |
|-|-|-|-|-|-|
| :heavy_check_mark: | cilium_feature_adv_connect_and_lb_big_tcp_enabled | protocol=ipv4-only | 1 | 1 | 1 |
| :heavy_check_mark: |  | protocol=ipv6-only | 0 | 0 | 0 |
| :warning: | cilium_feature_adv_connect_and_lb_envoy_proxy_enabled |  | 1 | 0 | 0 |
`,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := printPerNodeFeatureStatus(tt.args.nodeMap, tt.args.sp(&tt.args.buffer)); (err != nil) != tt.wantErr {
				t.Errorf("printPerNodeFeatureStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.args.expectedResult, tt.args.buffer.String())
		})
	}
}
