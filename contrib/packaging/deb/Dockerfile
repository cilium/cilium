FROM ubuntu:16.04

LABEL maintainer "Eloy Coto <eloy.coto@gmail.com>"
ENV GOLANG_VERSION 1.9

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dh-golang devscripts fakeroot dh-make clang git libdistro-info-perl \
        dh-systemd build-essential curl gcc make libc6-dev.i386 \
        python-docutils ca-certificates git-buildpackage llvm && \
    curl -Sslk -o go.tar.gz \
        "https://storage.googleapis.com/golang/go${GOLANG_VERSION}.linux-amd64.tar.gz" && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz && \
    export PATH="/usr/local/go/bin:$PATH"; \
    go version; \
    mkdir -p /opt/cilium/

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

ADD . /opt/cilium

VOLUME ["/output"]
ENTRYPOINT /opt/cilium/create_deb.sh
