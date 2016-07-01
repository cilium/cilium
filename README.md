# Cilium

Cilium provides fast and low latency in-kernel networking connectivity and
security policy enforcement for containers based on eBPF.

Cilium is...
 * **simple:**
   Every container is assigned a unique address and connected to a single flat
   virtual network providing connectivity between all containers and to external
   endpoints. The security layer on top allows to specify security policies
   based on container labels independently from the address model and location
   of the container.
 * **fast:**
   The BPF JIT compiler integrated into the Linux kernel guarantees for
   efficient execution of BPF programs. A separate BPF programs is generated for
   each individual container on the fly which allows to automatically reduce the
   code size to the minimal, similar to static linking.
 * **forward-looking:**
   A modern IPv6 based addressing model ensures scalability as clusters grow
   beyond the available address space of IPv4. IPv4 connectivity is provided
   for backwards compatibility. The transition is further assisted with the help
   of NAT46 and DNS46 which provides IPv4 connectivity to IPv6-only
   applications.
 * **debuggable:**
   A highly efficient monitoring subsystem is integrated and can be enabled on
   demand at runtime. It provides visibility into the network activity of
   containers under high network speeds without disruption or introduction of
   latency.
 * **hotfixable:**
   Updates, in particular security fixes, can be applied without the need to
   migrate or restart any of the served containers.
 * **extendable:**
   Advanced users can extend and customize any aspect of the BPF programs
   without the recompilation of the kernel or restarting of containers. This
   may include the addition of additional statistics not provided by the Linux
   kernel, support for additional protocol parsers, modifications of the
   connection tracker or policy layer, additional forwarding logic, etc.

## Networking Model

The networking model provided by Cilium is kept as simple as possible and has
been designed for users of containers to not require knowledge of networking.
Each container receives a unique address which empowers the container to
initiate connections to any other container or external endpoints as long as the
policy allows it. Complexity caused by integration into physical or virtual
networks is hidden from container users.

Integration to other networks is available in various forms including native
routing for physically trusted environments and encapsulation for environments
where middle boxes can't be trusted, e.g. the internet or a public cloud. For
additional information, see [networking model](doc/model.md).

## Prerequisites

The experimental nature of Cilium currently requires a recent version of the
Linux kernel iproute2 and clang+LLVM. Specifically:
  * Linux kernel: https://git.breakpoint.cc/cgit/dborkman/net-next.git/log/?h=bpf-wip
  * iproute2: https://git.breakpoint.cc/cgit/dborkman/iproute2.git/log/?h=bpf-wip
  * clang+LLVM: 3.7.1

All changes to the Linux kernel have been merged upstream and will become
available in distribution kernels soon.

To ease first trial steps, you may use the vagrant environment which provides
all Prerequisites and automatically installs cilium:
[vagrant instructions](doc/vagrant.md).

## Installation

Cilium consists of an agent which must be installed on all servers which
will run containers. See [installation instructions](doc/installation.md) for
detailed instructions how to install Cilium.

## Integration with orchestration systems

Cilium provides integration plugins for the following orchestration systems:
  * CNI (Kubernetes/Mesos) [Installation instructions](doc/k8s.md)
  * libnetwork (Docker) [Installation instructions](doc/docker.md)

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
$ sudo cilium daemon run -d eth0
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
