# Envoy binary for Istio sidecar proxy

The integration of Cilium and Istio requires building artifacts from
several repositories in order to build Docker images.  Some of those
artifacts require changes that have not yet been merged upstream.

This document provides the instructions to build the Cilium-specific
Istio images.

## Build the Istio binaries

Build the Istio binaries, especially a `pilot-discovery` modified to
configure Cilium filters in every HTTP filter chain.  This work is
being developed in Cilium's `inject-cilium-filters` branch, which is
based on Istio's release-1.0 branch.

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

    TAG=1.0.0 make docker.pilot

The `istio/proxytproxy` and `istio/proxytproxy_debug` for pre-releases are not
available on Docker Hub. If the version built is a pre-release, build
them here:

    TAG=1.0.0 make docker.proxytproxy docker.proxytproxy_debug

## Build Cilium's sidecar proxy Docker images

    mkdir -p ${GOPATH}/src/github.com/cilium
    cd ${GOPATH}/src/github.com/cilium
    git clone git@github.com:cilium/cilium.git
    cd cilium/envoy
    make docker-istio-proxy docker-istio-proxy-debug

## Push the Docker images to Docker Hub

    docker login -u ...
    docker image push cilium/istio_pilot:1.0.0
    docker image push cilium/istio_proxy:1.0.0
    docker image push cilium/istio_proxy_debug:1.0.0
