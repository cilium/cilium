// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestQualifyHTTPFiltersExternalProcessors(t *testing.T) {
	tests := map[string]struct {
		cluster string
		want    string
		updated bool
	}{
		"inference endpoint picker": {
			cluster: "epp:default:picker:9002:FailOpen",
			want:    "default/gateway/epp:default:picker:9002:FailOpen",
			updated: true,
		},
		"extension ref processor": {
			cluster: "grpc:default:processor:9001",
			want:    "default/gateway/grpc:default:processor:9001",
			updated: true,
		},
		"already qualified processor": {
			cluster: "default/gateway/grpc:default:processor:9001",
			want:    "default/gateway/grpc:default:processor:9001",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config := &extprocv3.ExternalProcessor{
				GrpcService: &corev3.GrpcService{
					TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
							ClusterName: tc.cluster,
							Authority:   "processor:9001",
						},
					},
				},
				FailureModeAllow: true,
				MessageTimeout:   durationpb.New(17 * time.Second),
				ProcessingMode: &extprocv3.ProcessingMode{
					RequestBodyMode: extprocv3.ProcessingMode_BUFFERED,
				},
			}
			// Qualification must preserve fields unknown to this control-plane version.
			config.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			expected := proto.Clone(config).(*extprocv3.ExternalProcessor)
			expected.GrpcService.GetEnvoyGrpc().ClusterName = tc.want
			filter := &hcmv3.HttpFilter{
				Name: "envoy.filters.http.ext_proc/default/processor",
				ConfigType: &hcmv3.HttpFilter_TypedConfig{
					TypedConfig: toAny(config),
				},
			}
			hcm := &hcmv3.HttpConnectionManager{HttpFilters: []*hcmv3.HttpFilter{filter}}

			updated, err := qualifyHttpFilters("default", "gateway", hcm)
			require.NoError(t, err)
			require.Equal(t, tc.updated, updated)
			require.Equal(t, "envoy.filters.http.ext_proc/default/processor", filter.Name)
			actual := &extprocv3.ExternalProcessor{}
			require.NoError(t, filter.GetTypedConfig().UnmarshalTo(actual))
			require.True(t, proto.Equal(expected, actual), "only the cluster reference should change")

			updated, err = qualifyHttpFilters("default", "gateway", hcm)
			require.NoError(t, err)
			require.False(t, updated, "qualification must be idempotent")
		})
	}
}

func TestQualifyHTTPFiltersExternalProcessorWithoutEnvoyGRPC(t *testing.T) {
	for name, service := range map[string]*corev3.GrpcService{
		"no gRPC service": nil,
		"no target":       {},
		"Google gRPC": {
			TargetSpecifier: &corev3.GrpcService_GoogleGrpc_{
				GoogleGrpc: &corev3.GrpcService_GoogleGrpc{TargetUri: "processor:9001"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := toAny(&extprocv3.ExternalProcessor{GrpcService: service})
			hcm := &hcmv3.HttpConnectionManager{HttpFilters: []*hcmv3.HttpFilter{{
				Name: "envoy.filters.http.ext_proc",
				ConfigType: &hcmv3.HttpFilter_TypedConfig{
					TypedConfig: config,
				},
			}}}
			original := proto.Clone(hcm)

			updated, err := qualifyHttpFilters("default", "gateway", hcm)
			require.NoError(t, err)
			require.False(t, updated)
			require.True(t, proto.Equal(original, hcm))
		})
	}
}
