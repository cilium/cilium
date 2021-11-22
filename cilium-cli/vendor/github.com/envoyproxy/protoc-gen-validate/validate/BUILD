load("@com_google_protobuf//:protobuf.bzl", "py_proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_java//java:defs.bzl", "java_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility =
        ["//visibility:public"],
)

proto_library(
    name = "validate_proto",
    srcs = ["validate.proto"],
    deps = [
        "@com_google_protobuf//:descriptor_proto",
        "@com_google_protobuf//:duration_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "validate_cc",
    deps = [":validate_proto"],
)

py_proto_library(
    name = "validate_py",
    srcs = ["validate.proto"],
    deps = ["@com_google_protobuf//:protobuf_python"],
)

go_proto_library(
    name = "go_default_library",
    importpath = "github.com/envoyproxy/protoc-gen-validate/validate",
    proto = ":validate_proto",
)

cc_library(
    name = "cc_validate",
    hdrs = ["validate.h"],
)

java_proto_library(
    name = "validate_java",
    deps = [":validate_proto"],
)
