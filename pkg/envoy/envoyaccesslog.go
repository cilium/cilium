// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"encoding/json"

	envoy_config_accesslog_v3 "github.com/cilium/proxy/go/envoy/config/accesslog/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_access_loggers_file_v3 "github.com/cilium/proxy/go/envoy/extensions/access_loggers/file/v3"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	logFormatTextType = "text"
	logFormatJsonType = "json"
)

type AccessLogParams struct {
	Enabled bool   `mapstructure:"proxy-accesslog-enabled"`
	Path    string `mapstructure:"proxy-accesslog-path"`
	Format  string `mapstructure:"proxy-accesslog-format"`
	Pattern string `mapstructure:"proxy-accesslog-pattern"`
}

func (params AccessLogParams) Flags(flags *pflag.FlagSet) {
	flags.Bool("proxy-accesslog-enabled", params.Enabled, "Enable Envoy Proxy Access Log")
	flags.String("proxy-accesslog-path", params.Path, "Proxy Access Log path. Defaults to /dev/stdout")
	flags.String("proxy-accesslog-format", params.Format, "Proxy Access Log format (e.g. json or text)")
	flags.String("proxy-accesslog-pattern", params.Pattern, "Proxy Access Log string pattern")
}

func InitEnvoyAccessLog(params AccessLogParams) []*envoy_config_accesslog_v3.AccessLog {
	if !params.Enabled {
		return nil
	}

	var logFormat *envoy_access_loggers_file_v3.FileAccessLog_LogFormat
	var err error

	switch params.Format {
	case logFormatJsonType:
		logFormat, err = logFormatJson(params.Pattern)
	case logFormatTextType:
		logFormat, err = logFormatText(params.Pattern)
	}

	if err != nil {
		log.WithField("format", params.Format).Warn("Failed to parse access log format. Using the default format.")
		return nil
	}
	return []*envoy_config_accesslog_v3.AccessLog{
		{
			Name: "envoy.access_loggers.file",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_access_loggers_file_v3.FileAccessLog{
					Path:            params.Path,
					AccessLogFormat: logFormat,
				}),
			},
		},
	}
}

func logFormatText(pattern string) (*envoy_access_loggers_file_v3.FileAccessLog_LogFormat, error) {
	return &envoy_access_loggers_file_v3.FileAccessLog_LogFormat{
		LogFormat: &envoy_config_core.SubstitutionFormatString{
			Format: &envoy_config_core.SubstitutionFormatString_TextFormatSource{
				TextFormatSource: &envoy_config_core.DataSource{
					Specifier: &envoy_config_core.DataSource_InlineString{
						InlineString: pattern,
					},
				},
			},
			OmitEmptyValues: true,
		},
	}, nil
}

func logFormatJson(pattern string) (*envoy_access_loggers_file_v3.FileAccessLog_LogFormat, error) {
	m, err := toMap(pattern)
	if err != nil {
		return nil, err
	}

	jsonFormat := &structpb.Struct{
		Fields: make(map[string]*structpb.Value),
	}

	for k, v := range m {
		jsonFormat.Fields[k] = &structpb.Value{
			Kind: &structpb.Value_StringValue{
				StringValue: v,
			},
		}
	}

	return &envoy_access_loggers_file_v3.FileAccessLog_LogFormat{
		LogFormat: &envoy_config_core.SubstitutionFormatString{
			Format: &envoy_config_core.SubstitutionFormatString_JsonFormat{
				JsonFormat: jsonFormat,
			},
			OmitEmptyValues: true,
		},
	}, nil
}

func toMap(format string) (map[string]string, error) {
	var result map[string]string
	err := json.Unmarshal([]byte(format), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
