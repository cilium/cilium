licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_proto_library",
    "envoy_package",
)

envoy_package()

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":bpf_metadata_lib",
        ":cilium_l7_lib",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_proto_library(
    name = "accesslog_proto",
    srcs = ["accesslog.proto"],
)

envoy_cc_library(
    name = "cilium_l7_lib",
    srcs = [
        "accesslog.cc",
        "cilium_l7.cc",
    ],
    hdrs = [
        "accesslog.h",
        "cilium_l7.h",
    ],
    repository = "@envoy",
    deps = [
        ":accesslog_proto",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "bpf_metadata_lib",
    srcs = [
        "bpf.cc",
        "bpf_metadata.cc",
        "proxymap.cc",
    ],
    hdrs = [
        "bpf.h",
        "bpf_metadata.h",
        "proxymap.h",
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
    ],
)

envoy_cc_test(
    name = "cilium_integration_test",
    srcs = ["cilium_integration_test.cc"],
    data = ["cilium_proxy_test.json"],
    repository = "@envoy",
    deps = [
        ":bpf_metadata_lib",
        ":cilium_l7_lib",
        "@envoy//test/integration:integration_lib",
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
