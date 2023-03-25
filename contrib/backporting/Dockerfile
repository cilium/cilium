FROM ubuntu:20.04

LABEL maintainer="maintainer@cilium.io"
ARG GOLANG_VERSION=1.20.1

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y \
  git \
  jq \
  python3 \
  python3-pip \
  curl \
  vim

RUN curl -SsLk https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz -o - | tar -xz -C /usr/local

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
