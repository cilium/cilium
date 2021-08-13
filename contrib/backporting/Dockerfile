FROM ubuntu:20.04

LABEL maintainer="maintainer@cilium.io"

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y \
  git \
  jq \
  python3 \
  python3-pip \
  curl \
  vim
RUN pip3 install --user PyGithub
RUN mkdir -p /hub && \
    cd /hub \
    && curl -L -o hub.tgz https://github.com/github/hub/releases/download/v2.14.0/hub-linux-amd64-2.14.0.tgz \
    && tar xfz hub.tgz \
    && $(tar tfz hub.tgz | head -n1 | cut -f1 -d"/")/install \
    && rm -rf /hub
RUN useradd -m user
USER user
