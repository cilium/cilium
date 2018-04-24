licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_proto_library",
)

load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_proto_library",
)

api_proto_library(
    name = "cilium_bpf_metadata",
    srcs = ["cilium/cilium_bpf_metadata.proto"],
)

api_proto_library(
    name = "cilium_l7policy",
    srcs = ["cilium/cilium_l7policy.proto"],
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        # Cilium filters.
        ":cilium_bpf_metadata_lib",
        ":cilium_network_filter_lib",
        ":cilium_l7policy_lib",

        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_cc_binary(
    name = "istio-envoy",
    repository = "@envoy",
    deps = [
        # Cilium filters.
        ":cilium_bpf_metadata_lib",
        ":cilium_network_filter_lib",
        ":cilium_l7policy_lib",

        # Istio filters.
        # Cf. https://github.com/istio/proxy/blob/master/src/envoy/BUILD#L23
        "@istio_proxy//src/envoy/http/authn:filter_lib",
        "@istio_proxy//src/envoy/http/jwt_auth:http_filter_factory",
        "@istio_proxy//src/envoy/http/mixer:filter_lib",
        "@istio_proxy//src/envoy/tcp/mixer:filter_lib",
        # "@istio_proxy//src/envoy/alts:alts_socket_factory",

        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_proto_library(
    name = "accesslog_proto",
    srcs = ["cilium/accesslog.proto"],
)

# TODO: Replace has_services=1 with a new api_go_grpc_library target after rebasing to use data-plane-api's master.
api_proto_library(
    name = "npds",
    srcs = ["cilium/npds.proto"],
    has_services = 1,
    deps = [
        "@envoy_api//envoy/api/v2:discovery",
        "@envoy_api//envoy/api/v2/core:address",
        "@envoy_api//envoy/api/v2/route:route",
    ],
)

# TODO: Replace has_services=1 with a new api_go_grpc_library target after rebasing to use data-plane-api's master.
api_proto_library(
    name = "nphds",
    srcs = ["cilium/nphds.proto"],
    has_services = 1,
    deps = [
        "@envoy_api//envoy/api/v2:discovery",
    ],
)

envoy_cc_library(
    name = "cilium_socket_option_lib",
    hdrs = [
        "cilium_socket_option.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//source/common/common:logger_lib",
	":proxymap_lib",
    ],
)

api_proto_library(
    name = "config_source",
    srcs = [],
    deps = [
        "@envoy_api//envoy/api/v2/core:config_source",
    ],
)

envoy_cc_library(
    name = "grpc_subscription_lib",
    hdrs = [
        "grpc_subscription.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//source/common/config:subscription_factory_lib",
        ":config_source_cc",
    ],
)

envoy_cc_library(
    name = "cilium_l7policy_lib",
    srcs = [
        "accesslog.cc",
        "cilium_l7policy.cc",
        "cilium_network_policy.cc",
    ],
    hdrs = [
        "accesslog.h",
        "cilium_l7policy.h",
        "cilium_network_policy.h",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_socket_option_lib",
        ":accesslog_proto",
        ":cilium_l7policy_cc",
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/local_info:local_info_lib",
        ":npds_cc",
        ":grpc_subscription_lib",
    ],
)

envoy_cc_library(
    name = "proxymap_lib",
    srcs = [
        "bpf.cc",
        "proxymap.cc",
    ],
    hdrs = [
        "bpf.h",
        "linux/bpf.h",
        "linux/bpf_common.h",
        "linux/type_mapper.h",
        "proxymap.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
    ],
)

envoy_cc_library(
    name = "cilium_network_filter_lib",
    srcs = [
        "cilium_network_filter.cc",
    ],
    hdrs = [
        "cilium_network_filter.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry:registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        ":proxymap_lib",
        ":cilium_socket_option_lib",
    ],
)

envoy_cc_library(
    name = "cilium_bpf_metadata_lib",
    srcs = [
        "cilium_bpf_metadata.cc",
        "cilium_host_map.cc",
    ],
    hdrs = [
        "cilium_bpf_metadata.h",
        "cilium_host_map.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry:registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/local_info:local_info_lib",
        ":nphds_cc",
        ":proxymap_lib",
        ":cilium_bpf_metadata_cc",
        ":cilium_socket_option_lib",
        ":grpc_subscription_lib",
    ],
)

envoy_cc_test(
    name = "cilium_integration_test",
    srcs = ["cilium_integration_test.cc"],
    data = [
        "cilium_proxy_test.json",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_bpf_metadata_lib",
        ":cilium_network_filter_lib",
        ":cilium_l7policy_lib",
        "@envoy//test/integration:http_integration_lib",
    ],
)

sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":envoy"],
)

sh_binary(
    name = "check_format.py",
    srcs = ["@envoy//tools:check_format.py"],
    deps = [
        ":envoy_build_fixer.py",
        ":header_order.py",
    ],
)

sh_library(
    name = "header_order.py",
    srcs = ["@envoy//tools:header_order.py"],
)

sh_library(
    name = "envoy_build_fixer.py",
    srcs = ["@envoy//tools:envoy_build_fixer.py"],
)
