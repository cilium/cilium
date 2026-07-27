// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"strings"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_access_loggers_stream_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	ciliumFormatterGatewayName      = "%CILIUM_GATEWAY_NAME%"
	ciliumFormatterGatewayNamespace = "%CILIUM_GATEWAY_NAMESPACE%"
)

// ParseNodeLabelSelector parses a given string representation of a label selector into a metav1.LabelSelector.
// The representation is a comma-separated list of key-value pairs (key1=value1,key2=value2) that is used as MatchLabels.
// Values not matching these rules are skipped.
func ParseNodeLabelSelector(nodeLabelSelectorString string) *slim_metav1.LabelSelector {
	if nodeLabelSelectorString == "" {
		return nil
	}

	labels := map[string]string{}
	for v := range strings.SplitSeq(nodeLabelSelectorString, ",") {
		s := strings.Split(v, "=")
		if len(s) != 2 || len(s[0]) == 0 {
			continue
		}
		labels[s[0]] = s[1]
	}

	return &slim_metav1.LabelSelector{
		MatchLabels: labels,
	}
}

func toXdsResource(m proto.Message, typeUrl string) (ciliumv2.XDSResource, error) {
	protoBytes, err := proto.Marshal(m)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: typeUrl,
			Value:   protoBytes,
		},
	}, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}

func replaceCiliumAccessLogFormatters(nn types.NamespacedName, format string) string {
	format = strings.ReplaceAll(format, ciliumFormatterGatewayName, nn.Name)
	format = strings.ReplaceAll(format, ciliumFormatterGatewayNamespace, nn.Namespace)

	return format
}

func buildAccessLogJSONFormat(nn types.NamespacedName, format map[string]string) *envoy_config_core.SubstitutionFormatString {
	fields := make(map[string]*structpb.Value, len(format))
	for k, v := range format {
		if strings.Contains(v, ciliumFormatterGatewayName) || strings.Contains(v, ciliumFormatterGatewayNamespace) {
			v = replaceCiliumAccessLogFormatters(nn, v)
		}
		fields[k] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: v}}
	}
	return &envoy_config_core.SubstitutionFormatString{
		Format: &envoy_config_core.SubstitutionFormatString_JsonFormat{
			JsonFormat: &structpb.Struct{
				Fields: fields,
			},
		},
	}
}

func buildAccessLogTextFormat(nn types.NamespacedName, format string) *envoy_config_core.SubstitutionFormatString {
	format = replaceCiliumAccessLogFormatters(nn, format)
	return &envoy_config_core.SubstitutionFormatString{
		Format: &envoy_config_core.SubstitutionFormatString_TextFormatSource{
			TextFormatSource: &envoy_config_core.DataSource{
				Specifier: &envoy_config_core.DataSource_InlineString{
					InlineString: strings.TrimRight(format, "\n") + "\n",
				},
			},
		},
	}
}

func buildAccessLogFormat(nn types.NamespacedName, accessLog model.AccessLogs) *envoy_access_loggers_stream_v3.StdoutAccessLog_LogFormat {
	switch accessLog.Format {
	case model.AccessLogsFormatText:
		return &envoy_access_loggers_stream_v3.StdoutAccessLog_LogFormat{
			LogFormat: buildAccessLogTextFormat(nn, accessLog.Text),
		}
	case model.AccessLogsFormatJSON:
		return &envoy_access_loggers_stream_v3.StdoutAccessLog_LogFormat{
			LogFormat: buildAccessLogJSONFormat(nn, accessLog.JSON),
		}
	}

	return nil
}

func buildAccessLogs(nn types.NamespacedName, cfg []model.AccessLogs) []*envoy_config_accesslog_v3.AccessLog {
	accessLogs := make([]*envoy_config_accesslog_v3.AccessLog, 0, len(cfg))

	for _, accessLog := range cfg {
		accessLogs = append(accessLogs, &envoy_config_accesslog_v3.AccessLog{
			Name: "envoy.access_loggers.stdout",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_access_loggers_stream_v3.StdoutAccessLog{
					AccessLogFormat: buildAccessLogFormat(nn, accessLog),
				}),
			},
		})
	}

	return accessLogs
}

func getHTTPAccessLogs(m *model.Model) []*envoy_config_accesslog_v3.AccessLog {
	if !m.IsAccessLogsConfigured() {
		return nil
	}

	if !m.IsHTTPAccessLogsConfigured() {
		return nil
	}

	return buildAccessLogs(m.Telemetry.NamespacedName, m.Telemetry.AccessLogs[model.AccessLogsTargetHTTP])
}

func getTCPAccessLogs(m *model.Model) []*envoy_config_accesslog_v3.AccessLog {
	if !m.IsAccessLogsConfigured() {
		return nil
	}

	if !m.IsTCPAccessLogsConfigured() {
		return nil
	}

	return buildAccessLogs(m.Telemetry.NamespacedName, m.Telemetry.AccessLogs[model.AccessLogsTargetTCP])
}
