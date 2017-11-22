workspace(name = "envoy")

ENVOY_SHA = "06b9cda221a4be97752958d779c3e55bac49a6d1"

http_archive(
    name = "envoy",
    url = "https://github.com/jrajahalme/envoy/archive/" + ENVOY_SHA + ".zip",
    strip_prefix = "envoy-" + ENVOY_SHA,
)

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")
load("@envoy//bazel:cc_configure.bzl", "cc_configure")

envoy_dependencies()

cc_configure()

load("@envoy_api//bazel:repositories.bzl", "api_dependencies")
api_dependencies()
