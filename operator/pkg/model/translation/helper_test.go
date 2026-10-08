// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"testing"

	envoy_access_loggers_stream_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/operator/pkg/model"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestParseNodeLabelSelector(t *testing.T) {
	testCases := []struct {
		desc                  string
		input                 string
		expectedLabelSelector *slim_metav1.LabelSelector
	}{
		{
			desc:                  "Empty",
			input:                 "",
			expectedLabelSelector: nil,
		},
		{
			desc:  "Single label value",
			input: "a=b",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
			}},
		},
		{
			desc:  "Multiple label values",
			input: "a=b,c=d,e=f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": "f",
			}},
		},
		{
			desc:  "Empty key is not allowed",
			input: "a=b,c=d,=f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
			}},
		},
		{
			desc:  "Empty value",
			input: "a=b,c=d,e=",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": "",
			}},
		},
		{
			desc:  "No value",
			input: "a=b,c=d,e",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
			}},
		},
		{
			desc:  "Space before value",
			input: "a=b,c=d,e= f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": " f",
			}},
		},
		{
			desc:  "Space after value",
			input: "a=b,c=d,e=f ",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": "f ",
			}},
		},
		{
			desc:  "Space before key",
			input: "a=b,c=d, e=f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a":  "b",
				"c":  "d",
				" e": "f",
			}},
		},
		{
			desc:  "Space after key",
			input: "a=b,c=d,e =f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a":  "b",
				"c":  "d",
				"e ": "f",
			}},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			ls := ParseNodeLabelSelector(tC.input)

			assert.Equal(t, tC.expectedLabelSelector, ls)
		})
	}
}

func Test_buildAccessLogs(t *testing.T) {
	t.Run("text format", func(t *testing.T) {
		logs := buildAccessLogs(
			types.NamespacedName{
				Namespace: "default",
				Name:      "cilium",
			},
			[]model.AccessLogs{
				{
					Format: model.AccessLogsFormatText,
					Text:   "  %REQ(:METHOD)% %RESPONSE_CODE%  ",
				},
			})

		require.Len(t, logs, 1)
		require.Equal(t, "envoy.access_loggers.stdout", logs[0].GetName())

		stdout := &envoy_access_loggers_stream_v3.StdoutAccessLog{}
		require.NoError(t, proto.Unmarshal(logs[0].GetTypedConfig().GetValue(), stdout))

		format := stdout.GetLogFormat()
		require.NotNil(t, format)
		require.Equal(t,
			"  %REQ(:METHOD)% %RESPONSE_CODE%  \n",
			format.GetTextFormatSource().GetInlineString(),
		)
	})
	t.Run("text format with cilium-specific formatters", func(t *testing.T) {
		logs := buildAccessLogs(
			types.NamespacedName{
				Namespace: "default",
				Name:      "cilium",
			},
			[]model.AccessLogs{
				{
					Format: model.AccessLogsFormatText,
					Text:   "  [%CILIUM_GATEWAY_NAMESPACE%/%CILIUM_GATEWAY_NAME%] %REQ(:METHOD)% %RESPONSE_CODE%  ",
				},
			})

		require.Len(t, logs, 1)
		require.Equal(t, "envoy.access_loggers.stdout", logs[0].GetName())

		stdout := &envoy_access_loggers_stream_v3.StdoutAccessLog{}
		require.NoError(t, proto.Unmarshal(logs[0].GetTypedConfig().GetValue(), stdout))

		format := stdout.GetLogFormat()
		require.NotNil(t, format)
		require.Equal(t,
			"  [default/cilium] %REQ(:METHOD)% %RESPONSE_CODE%  \n",
			format.GetTextFormatSource().GetInlineString(),
		)
	})
	t.Run("json format", func(t *testing.T) {
		logs := buildAccessLogs(
			types.NamespacedName{
				Namespace: "default",
				Name:      "cilium",
			},
			[]model.AccessLogs{
				{
					Format: model.AccessLogsFormatJSON,
					JSON: map[string]string{
						"method":        "%REQ(:METHOD)%",
						"response_code": "%RESPONSE_CODE%",
					},
				},
			})

		require.Len(t, logs, 1)
		require.Equal(t, "envoy.access_loggers.stdout", logs[0].GetName())

		stdout := &envoy_access_loggers_stream_v3.StdoutAccessLog{}
		require.NoError(t, proto.Unmarshal(logs[0].GetTypedConfig().GetValue(), stdout))

		fields := stdout.GetLogFormat().GetJsonFormat().GetFields()
		require.Equal(t, "%REQ(:METHOD)%", fields["method"].GetStringValue())
		require.Equal(t, "%RESPONSE_CODE%", fields["response_code"].GetStringValue())
	})
	t.Run("json format with cilium-specific formatters", func(t *testing.T) {
		logs := buildAccessLogs(
			types.NamespacedName{
				Namespace: "default",
				Name:      "cilium",
			},
			[]model.AccessLogs{
				{
					Format: model.AccessLogsFormatJSON,
					JSON: map[string]string{
						"gateway":       fmt.Sprintf("%s/%s", ciliumFormatterGatewayNamespace, ciliumFormatterGatewayName),
						"method":        "%REQ(:METHOD)%",
						"response_code": "%RESPONSE_CODE%",
					},
				},
			})

		require.Len(t, logs, 1)
		require.Equal(t, "envoy.access_loggers.stdout", logs[0].GetName())

		stdout := &envoy_access_loggers_stream_v3.StdoutAccessLog{}
		require.NoError(t, proto.Unmarshal(logs[0].GetTypedConfig().GetValue(), stdout))

		fields := stdout.GetLogFormat().GetJsonFormat().GetFields()
		require.Equal(t, "default/cilium", fields["gateway"].GetStringValue())
		require.Equal(t, "%REQ(:METHOD)%", fields["method"].GetStringValue())
		require.Equal(t, "%RESPONSE_CODE%", fields["response_code"].GetStringValue())
	})
}

func Test_getHTTPAccessLogs(t *testing.T) {
	accessLogs := model.AccessLogs{
		Format: model.AccessLogsFormatText,
		Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
	}

	t.Run("not configured", func(t *testing.T) {
		require.Nil(t, getHTTPAccessLogs(nil))
		require.Nil(t, getHTTPAccessLogs(&model.Model{}))
		require.Nil(t, getHTTPAccessLogs(&model.Model{Telemetry: &model.Telemetry{}}))
	})

	t.Run("tcp target", func(t *testing.T) {
		logs := getHTTPAccessLogs(&model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetTCP: {accessLogs},
				},
			},
		})

		require.Nil(t, logs)
	})

	t.Run("http target", func(t *testing.T) {
		logs := getHTTPAccessLogs(&model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {accessLogs},
				},
			},
		})

		require.NotEmpty(t, logs)
	})

	t.Run("http and tcp targets", func(t *testing.T) {
		logs := getHTTPAccessLogs(&model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {accessLogs},
					model.AccessLogsTargetTCP:  {accessLogs},
				},
			},
		})

		require.NotEmpty(t, logs)
	})
}

func Test_getTCPAccessLogs(t *testing.T) {
	accessLogs := model.AccessLogs{
		Format: model.AccessLogsFormatText,
		Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
	}

	t.Run("not configured", func(t *testing.T) {
		require.Nil(t, getTCPAccessLogs(nil))
		require.Nil(t, getTCPAccessLogs(&model.Model{}))
		require.Nil(t, getTCPAccessLogs(&model.Model{Telemetry: &model.Telemetry{}}))
	})

	t.Run("http target", func(t *testing.T) {
		logs := getTCPAccessLogs(&model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {accessLogs},
				},
			},
		})

		require.Nil(t, logs)
	})

	t.Run("tcp target", func(t *testing.T) {
		logs := getTCPAccessLogs(&model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetTCP: {accessLogs},
				},
			},
		})

		require.NotEmpty(t, logs)
	})

	t.Run("http and tcp targets", func(t *testing.T) {
		logs := getTCPAccessLogs(&model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {accessLogs},
					model.AccessLogsTargetTCP:  {accessLogs},
				},
			},
		})

		require.NotEmpty(t, logs)
	})
}
