# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:b32efb0e682e74311b628df328dfd768108b92c2@sha256:0873607c0fc991c884bc7d39ea774c8ebd7df2be35f4b69b6d16b33ce871427b

# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:v1.25-4bb499dab5a0ec12a363c2c1834cf2a7707d0010@sha256:2ef282951e5e95c20644a8c8d02c13abf029d9cb29333380491aa1f268e40651 as cilium-envoy

#
# Cilium Proxy runtime install.
#
# cilium-runtime tag is a date on which the compatible runtime base
# was pushed.  If a new version of the runtime is needed, it needs to
# be tagged with a new date and this file must be changed accordingly.
# Keeping the old runtimes available will allow older versions to be
# built while allowing the new versions to make changes that are not
# backwards compatible.
#
FROM ${CILIUM_RUNTIME_IMAGE} as release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
RUN echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
COPY --from=cilium-envoy / /

ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium-envoy"]
