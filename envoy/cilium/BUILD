licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_proto_library",
)

load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_proto_library",
)

api_proto_library(
    name = "cilium_bpf_metadata",
    srcs = ["cilium_bpf_metadata.proto"],
    visibility = ["//visibility:public"],
)

api_proto_library(
    name = "cilium_network_filter",
    srcs = ["cilium_network_filter.proto"],
    visibility = ["//visibility:public"],
)

api_proto_library(
    name = "cilium_l7policy",
    srcs = ["cilium_l7policy.proto"],
    visibility = ["//visibility:public"],
)

envoy_proto_library(
    name = "accesslog_proto",
    srcs = ["accesslog.proto"],
)

# TODO: Replace has_services=1 with a new api_go_grpc_library target after rebasing to use data-plane-api's master.
api_proto_library(
    name = "npds",
    srcs = ["npds.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/api/v2:discovery_export",
        "@envoy_api//envoy/api/v2/core:address_export",
        "@envoy_api//envoy/api/v2/route:route_export",
    ],
)

# TODO: Replace has_services=1 with a new api_go_grpc_library target after rebasing to use data-plane-api's master.
api_proto_library(
    name = "nphds",
    srcs = ["nphds.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/api/v2:discovery_export",
    ],
)
