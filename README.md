# Cilium Networking

Cilium networking is an experimental project solving container connectivity
with a radical new aporach: Small BPF programs are specifically generated
on the fly for each container to implement connectivty between containers
and other endpoints.

The Cilium model offers great benefits over traditional fixed or configurable
networking elements:
  * Much like unikernels, programs are only as big as absolutely required.
    Functionality can be compiled in or out on the fly even while a
    container is running.
  * The programs are Just in Time (JIT) compiled into CPU instructions in the
    Linux kernel for maximum performance (no virtual machine).
  * Own or third party protocol parsers, custom forwarding logic, additional
    statistical counters can be added and removed on the fly.
  * The tracing/perf subsystem can be leveraged for completely programmable
    visibility into the networking layers of each application container.

## Networking Model

The standard networking model provided by Cilium is kept as simple as
possible and has been designed with the requirement that it is usable
any prior knowledge of networking:
  * Routing only. Like on the interwebs.
  * No networks, no subnets, no VLANs, no broadcast domains.
  * Any container can be connected to any other container through a labels
    based policy system. Groups of containers can be isolated at will
    based on labels. No need to put a container onto multiple networks.
  * No need for any sort of centralized controller
  * Host scope address allocation only. No need for containers to have an
    address in a particular network. No need for nodes to negotiate
    addresses. Addressing is decoupled from the desired isolation guarantees.
  * Path to a native IPv6 cluster transition for maximum scale while providing
    backwards compatibility to legacy IPv4 endpoints for as long as needed.

For additional details, see the [doc/model.MD]

## Requirements

Cilium's experimental nature requires a recent version of the Linux kernel,
iproute2 and clang+LLVM. Specifically:
  * Linux kernel: https://git.breakpoint.cc/cgit/dborkman/net-next.git/log/?h=bpf-wip
  * iproute2: https://git.breakpoint.cc/cgit/dborkman/iproute2.git/log/?h=bpf-wip
  * clang+LLVM: 3.7.1

The respective changes have been upstreamed and as distributions rebase, the
minimal requirements will be met by any major distribution.

To ease installation and trial, we are providing a prebuilt Vagrant box plus a
Vagrantfile to build, deploy & run Cilium:

```
$ vagrant up
```

Alternatively you can use the vagrant box directly and install yourself:

  ```
  $ vagrant init noironetworks/net-next
  $ vagrant up
  ```
## Integration

Cilium provides integration plugins for the following orchestration systems:
  * CNI (Kubernetes/CoreOS)
  * libnetwork (Docker)
  * Mesos (Soon(TM))

## Getting Started

The following examples are based on the Vagrantfile provided. If you have
manually installed Cilium, you need to ensure that all the services are
running.

You may also run CNI and libnetwork owned containers at the same time.
They will both be treated equally and can reach each other.

### CNI - Kubernetes

A CNI plugin is provided to integrate Cilium with Kubernetes or any other
platform which relies on CNI. The `make install` command in the `cni`
directory will deploy the plugin.

```
$ vagrant up k8s1
```

### Docker

Docker supports requires to start both `cilium-net-daemon` and
`cilium-docker`.

Cilium does not require to define networks. Isolation and multi tenancy is
implemented based on labels through policy. However, libnetwork requires
to specifiy a network in order to invoke a non Docker plugin. For this
purpose, the cilium daemon will automatically create a Docker network
"cilium" which can be used to attach all containers to. In case the network
is not available, you may create it yourself:

```
$ docker network create --driver cilium --ipam-driver cilium cilium
```

Running a container with Cilium networking connectivity is then achieved
by specifying the `--net` argument:

```
$ docker run -ti --rm --net cilium ubuntu bash
```

### Native Routing Mode

In direct routing mode, Cilium will attach itself to a network device
and automatically pick up all packets to local containers. Similarly
packets which are addressed to a non local container will be handed
over to the normal Linux stack and are thus routed through the regular
mechanisms. This allows you to run a routing daemon to distribute the
host routes across all cluster nodes.

In order to enable direct routing mode, run Cilium with the `-d` option
and provided the interface name to listen on.

```
$ sudo cilium daemon -d eth0
```

### Overlay Mode

In overlay mode, packets addressed to non local nodes will be encapsulated
in a UDP packet using either Geneve or VXLAN. This reduces the need to
distribute routes across compute node, the underlying networking requirement
is reduced to simple UDP connectivity among cluster nodes. It also allows
to send IPv6 container traffic across a IPv4 only network.

Overlay mode is the default if `-d INTERFACE` is not provided.

## Testsuite

The testsuite can be run on a vagrant box:

   ```
   $ vagrant provision --provision-with testsuite
   ```

or manually on the local machine:

   ```
   $ sudo make runtime-tests
   ```
