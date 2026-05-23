// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	dynModuleName = "cilium_dynamic_modules"

	listenerFilterDynModName    = "envoy.extensions.filters.listener.dynamic_modules"
	listenerFilterDynModTypeURL = "type.googleapis.com/envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter"
	httpFilterDynModName        = "envoy.extensions.filters.http.dynamic_modules"
	httpFilterDynModTypeURL     = "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter"
	networkFilterDynModName     = "envoy.extensions.filters.network.dynamic_modules"
	networkFilterDynModTypeURL  = "type.googleapis.com/envoy.extensions.filters.network.dynamic_modules.v3.DynamicModuleNetworkFilter"
)

func wrapListenerFilterAsDynamicModule(filterName string, config proto.Message) *envoy_config_listener.ListenerFilter {
	return &envoy_config_listener.ListenerFilter{
		Name: listenerFilterDynModName,
		ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
			TypedConfig: buildDynModuleAny(listenerFilterDynModTypeURL, filterName, config),
		},
	}
}

func wrapHttpFilterAsDynamicModule(filterName string, config proto.Message) *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: httpFilterDynModName,
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: buildDynModuleAny(httpFilterDynModTypeURL, filterName, config),
		},
	}
}

func wrapNetworkFilterAsDynamicModule(filterName string, config proto.Message) *envoy_config_listener.Filter {
	return &envoy_config_listener.Filter{
		Name: networkFilterDynModName,
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: buildDynModuleAny(networkFilterDynModTypeURL, filterName, config),
		},
	}
}

// buildDynModuleAny constructs the Any-typed config for a dynamic module filter.
// Wire format:
//
//	DynamicModule*Filter {
//	  field 1 (dynamic_module_config): DynamicModuleConfig { field 1 (name): "cilium_dynamic_modules" }
//	  field 2 (filter_name): <filterName>
//	  field 3 (filter_config): Any { type_url: "type.googleapis.com/google.protobuf.BytesValue", value: <config bytes> }
//	}
func buildDynModuleAny(typeURL string, filterName string, config proto.Message) *anypb.Any {
	configBytes, err := proto.Marshal(config)
	if err != nil {
		panic("dynamic_module_wrappers: failed to marshal filter config: " + err.Error())
	}

	bytesValue := &wrapperspb.BytesValue{Value: configBytes}
	filterConfigAny, err := anypb.New(bytesValue)
	if err != nil {
		panic("dynamic_module_wrappers: failed to wrap as BytesValue Any: " + err.Error())
	}

	moduleConfigBytes := protoMarshalLengthDelimited(1, protoMarshalString(1, dynModuleName))
	filterNameBytes := protoMarshalString(2, filterName)

	filterConfigAnyBytes, err := proto.Marshal(filterConfigAny)
	if err != nil {
		panic("dynamic_module_wrappers: failed to marshal filter config Any: " + err.Error())
	}
	filterConfigField := protoMarshalLengthDelimited(3, filterConfigAnyBytes)

	fullValue := make([]byte, 0, len(moduleConfigBytes)+len(filterNameBytes)+len(filterConfigField))
	fullValue = append(fullValue, moduleConfigBytes...)
	fullValue = append(fullValue, filterNameBytes...)
	fullValue = append(fullValue, filterConfigField...)

	return &anypb.Any{
		TypeUrl: typeURL,
		Value:   fullValue,
	}
}

func protoMarshalString(fieldNumber int, s string) []byte {
	tag := byte((fieldNumber << 3) | 2)
	data := []byte(s)
	return append(append([]byte{tag}, protoEncodeVarint(uint64(len(data)))...), data...)
}

func protoMarshalLengthDelimited(fieldNumber int, data []byte) []byte {
	tag := byte((fieldNumber << 3) | 2)
	return append(append([]byte{tag}, protoEncodeVarint(uint64(len(data)))...), data...)
}

func protoEncodeVarint(x uint64) []byte {
	var buf []byte
	for x >= 0x80 {
		buf = append(buf, byte(x)|0x80)
		x >>= 7
	}
	buf = append(buf, byte(x))
	return buf
}

func WrapListenerFilterAsDynamicModule(filterName string, config proto.Message) *envoy_config_listener.ListenerFilter {
	return wrapListenerFilterAsDynamicModule(filterName, config)
}

func WrapNetworkFilterAsDynamicModule(filterName string, config proto.Message) *envoy_config_listener.Filter {
	return wrapNetworkFilterAsDynamicModule(filterName, config)
}

// buildDynamicModuleBootstrapAny constructs the bootstrap extension Any for loading
// the cilium_dynamic_modules shared library at Envoy startup.
// Wire format: DynamicModuleConfig { name: "cilium_dynamic_modules", do_not_close: true }
func buildDynamicModuleBootstrapAny() *anypb.Any {
	nameField := protoMarshalString(1, dynModuleName)
	// field 2 (do_not_close): varint bool = 1
	doNotCloseField := []byte{(2 << 3) | 0, 1}

	value := make([]byte, 0, len(nameField)+len(doNotCloseField))
	value = append(value, nameField...)
	value = append(value, doNotCloseField...)

	return &anypb.Any{
		TypeUrl: "type.googleapis.com/envoy.extensions.dynamic_modules.v3.DynamicModuleConfig",
		Value:   value,
	}
}
