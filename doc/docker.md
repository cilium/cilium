# Cilium Docker Plugin

The Cilium docker plugin provides integration of Cilium with Docker. The plugin
will automatically handle network connectivity and/or address allocation (IPAM)
requests for any network of type "cilium".

## Installation

NOTE: This plugin currently depends on the following change to allow for IPv6
only containers which has not been merged yet:
https://github.com/docker/libnetwork/pull/826

The plugin consists of a single binary `cilium-docker` which can be installed
in any location. For connectivity to the Cilium daemon, the UNIX domain socket
of the daemon must be reachable via the local filesystem.

Various templates for integration with service management tools such as
upstart or systemd can be found in the [`contrib/`](../contrib) directory.

## Usage

Attaching a container to Cilium is done by attaching the container to a network
of type "cilium". Such a network can be created as follows:

```
$ docker network create --driver cilium --ipam-driver cilium cilium
$ docker run --net cilium hello-world
```

The security and isolation model of Cilium is solely based on container labels.
It is therefore not required to create multiple networks for the purpose of
creating isolation boundaries. It is possible to create multiple Cilium
networks although doing so will not have any effect, Cilium will treat all
attached containers as a single namespace and enforce security based on
container labels.

## Address Management (IPAM)

The `cilium-docker` plugin will allocate an unique IPv6 address out of the
address prefix assigned to the container host. See [here](model.md#prefix-list) for
additional information on the addressing model of Cilium.
