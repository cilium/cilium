# Envoy binary for Istio sidecar proxy

The integration of Cilium and Istio requires building artifacts from
several repositories in order to build Docker images.  Some of those
artifacts require changes that have not yet been merged upstream.

This document provides the instructions to build the Cilium-specific
Istio images.

## Build the Istio binaries

Build the Istio binaries, especially a `pilot-discovery` modified to
configure Cilium filters in every HTTP filter chain.  This work is
still being developed in Cilium's `inject-cilium-filters` branch.

    mkdir -p ${GOPATH}/src/istio.io
    cd ${GOPATH}/src/istio.io
    git clone git@github.com:cilium/istio.git
    git checkout inject-cilium-filters
    git submodule sync
    git submodule update --init --recursive --remote
    git submodule update --force --checkout
    make build

## Build the required upstream Istio Docker images

Only one image needs to be built: `cilium/istio_pilot`.

    TAG=0.8.0 make docker.pilot

The `istio/proxy` and `istio/proxy_debug` for pre-releases are not
available on Docker Hub. If the version built is a pre-release, build
them here:

    TAG=0.8.0 make docker.proxy docker.proxy_debug

## (Optional) Check that the upstream proxy Docker images are consistent

Build the upstream proxy images to check them:

    TAG=0.8.0 make docker.proxy_init docker.proxyv2 docker.proxy_debugv2

### `istio/proxy_init`

    docker run --rm -it --cap-add=NET_ADMIN --entrypoint /bin/bash istio/proxy_init:0.8.0

In the container, run the iptables configuration script with various
combinations of parameters, for example:

    /usr/local/bin/istio-iptables.sh -p 15001 -u 1337 -m TPROXY -b '*'
    /usr/local/bin/istio-iptables.sh -p 15001 -u 1337 -m TPROXY -b 1234,5678
    /usr/local/bin/istio-iptables.sh -p 15001 -u 1337 -m TPROXY -b '*' -d 1234,5678

For each combination, check the iptables and routing tables and rules:

    iptables -v -t nat -L
    iptables -v -t mangle -L
    ip rule
    ip route show table 133

### `istio/proxyv2`

    docker run --rm -it --entrypoint /bin/bash istio/proxyv2:0.8.0

Check that the binaries have the right size, mode, owner, and group.

    stat /usr/local/bin/{envoy,pilot-agent}

Check that the Envoy bootstrap configures Envoy v2 API and ADS (not v1 API):

    cat /var/lib/istio/envoy/envoy_bootstrap_tmpl.json

### `istio/proxy_debugv2`

    docker run --rm -it --entrypoint /bin/bash istio/proxy_debugv2:0.8.0

Check that the binaries have the right size, mode, owner, and group.

    stat /usr/local/bin/{envoy,pilot-agent}

Check that the Envoy bootstrap configures Envoy v2 API and ADS (not v1 API):

    cat /var/lib/istio/envoy/envoy_bootstrap_tmpl.json

## Make sure that the Envoy bootstrap file is up-to-date

The file is at `envoy/envoy_bootstrap_tmpl.json` and extends the
upstream version to configure Envoy to use API v2 and to define the
`xds-grpc-cilium` cluster used by the Cilium filters to connect to
Cilium agent via a Unix domain socket.  The upstream version is at
https://github.com/istio/istio/blob/release-0.8/tools/deb/envoy_bootstrap_v2.json

## Build Cilium's sidecar proxy Docker images

    mkdir -p ${GOPATH}/src/github.com/cilium
    cd ${GOPATH}/src/github.com/cilium
    git clone git@github.com:cilium/cilium.git
    cd cilium/envoy
    make docker-istio-proxy docker-istio-proxy-debug

## Push the Docker images to Docker Hub

    docker login -u ...
    docker image push cilium/istio_pilot:0.8.0
    docker image push cilium/istio_proxy:0.8.0
    docker image push cilium/istio_proxy_debug:0.8.0
