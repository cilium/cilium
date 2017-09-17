package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_test(
    name = "go_default_test",
    srcs = [
        "jsonpath_test.go",
        "parser_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "doc.go",
        "jsonpath.go",
        "node.go",
        "parser.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/k8s.io/client-go/third_party/forked/golang/template:go_default_library"],
)
