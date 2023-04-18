ARG GOLANG_IMAGE=docker.io/library/golang:1.20.2@sha256:5990c4fbb1ab074b4be7bcc9ee3b8bd2888a1d4f9572fc7d63b804ea5da54e73

FROM $GOLANG_IMAGE as golang

FROM ubuntu:20.04
COPY --from=golang /usr/local/go /usr/local/go

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y \
  git \
  jq \
  python3 \
  python3-pip \
  curl \
  vim

RUN set -ex \
  && mkdir -p /hub \
  && cd /hub \
  && HUB_ARCH=amd64; if [ "$(uname -m)" = "aarch64" ]; then HUB_ARCH=arm64; fi \
  && curl -L -o hub.tgz https://github.com/github/hub/releases/download/v2.14.0/hub-linux-${HUB_ARCH}-2.14.0.tgz \
  && tar xfz hub.tgz \
  && $(tar tfz hub.tgz | head -n1 | cut -f1 -d"/")/install \
  && rm -rf /hub
RUN useradd -m user
USER user
ENV PATH /usr/local/go/bin:$PATH
RUN pip3 install --user PyGithub

LABEL maintainer="maintainer@cilium.io"
