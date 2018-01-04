workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_SHA = "bc9069a8906cdcdb5f90df27b8b1df1a7f5f6f84"

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
