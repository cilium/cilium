package(default_visibility = ["//visibility:public"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_library(
    name = "go_default_library",
    srcs = [
        "aws.go",
        "aws_instancegroups.go",
        "aws_loadbalancer.go",
        "aws_metrics.go",
        "aws_routes.go",
        "aws_utils.go",
        "device_allocator.go",
        "instances.go",
        "log_handler.go",
        "regions.go",
        "retry_handler.go",
        "sets_ippermissions.go",
        "tags.go",
        "volumes.go",
    ],
    deps = [
        "//pkg/api/v1/service:go_default_library",
        "//pkg/cloudprovider:go_default_library",
        "//pkg/controller:go_default_library",
        "//pkg/credentialprovider/aws:go_default_library",
        "//pkg/kubelet/apis:go_default_library",
        "//pkg/volume:go_default_library",
        "//pkg/volume/util:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/awserr:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/credentials:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/ec2metadata:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/request:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/session:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/autoscaling:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/ec2:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/elb:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/kms:go_default_library",
        "//vendor/github.com/golang/glog:go_default_library",
        "//vendor/github.com/prometheus/client_golang/prometheus:go_default_library",
        "//vendor/gopkg.in/gcfg.v1:go_default_library",
        "//vendor/k8s.io/api/core/v1:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/types:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/util/sets:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/util/wait:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = [
        "aws_loadbalancer_test.go",
        "aws_test.go",
        "device_allocator_test.go",
        "instances_test.go",
        "regions_test.go",
        "retry_handler_test.go",
        "tags_test.go",
    ],
    library = ":go_default_library",
    deps = [
        "//pkg/kubelet/apis:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/autoscaling:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/ec2:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/elb:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/service/kms:go_default_library",
        "//vendor/github.com/golang/glog:go_default_library",
        "//vendor/github.com/stretchr/testify/assert:go_default_library",
        "//vendor/github.com/stretchr/testify/mock:go_default_library",
        "//vendor/k8s.io/api/core/v1:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/apis/meta/v1:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/types:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/util/sets:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
)
