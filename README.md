<img src="https://cdn.rawgit.com/cilium/cilium/master/Documentation/images/logo.svg" alt="Cilium Logo" width="350" />

[![Build Status](https://jenkins.cilium.io/job/cilium/job/cilium/job/master/badge/icon)](https://jenkins.cilium.io/job/cilium/job/cilium/job/master/)
[![Go Report Card](https://goreportcard.com/badge/github.com/cilium/cilium)](https://goreportcard.com/report/github.com/cilium/cilium)
[![GoDoc](https://godoc.org/github.com/cilium/cilium?status.svg)](https://godoc.org/github.com/cilium/cilium)
[![Read the Docs](https://readthedocs.org/projects/docs/badge/?version=latest)](http://cilium.readthedocs.io/en/latest/)
[![Apache licensed](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/cilium/cilium/blob/master/LICENSE)
[![GPL licensed](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/cilium/cilium/blob/master/bpf/COPYING)
[![Join the Cilium slack channel](https://cilium.herokuapp.com/badge.svg)](https://cilium.herokuapp.com/)

Cilium is open source software for providing and transparently securing network
connectivity and loadbalancing between application workloads such as
application containers or processes. Cilium operates at Layer 3/4 to provide
traditional networking and security services as well as Layer 7 to protect and
secure use of modern application protocols such as HTTP, gRPC and Kafka. Cilium
is integrates to common orchestration frameworks such as Kubernetes and Mesos.

A new Linux kernel technology called BPF is at the foundation of Cilium. It
supports dynamic insertion of BPF bytecode into the Linux kernel at various
integration points such as: network IO, application sockets, and traceptions to
implement security, networking and visibility logic. BPF is highly efficient
and flexible. To learn more about BPF, read mode in our our extensive [BPF
reference guide][bpf-reference].

<p align="center">
   <img src="Documentation/images/cilium-arch.png" />
</p>

## Functionality Overview

 * **Protect and secure APIs transparently:** Ability to secure modern
   application protocols such as REST/HTTP, gRPC and Kafka. Traditional
   firewalls operates at Layer 3 and 4. A protocol running on a particular port
   is either completely trusted or blocked entirely. Cilium provides the ability
   to filter on individual application protocol requests such as:

   - Allow all HTTP requests with method `GET` and path `/public/.*`. Deny all
     other requests.
   - Allow `service1` to produce on Kafka topic `topic1` and `service2` to
     consume on `topic1`. Reject all other Kafka messages.
   - Require the HTTP header `X-Token: [0-9]+` to be present in all REST calls.

   See the section [Layer 7 Protocol Enforcement][l7-proto] in our
   documentation for the latest list of supported protocols and examples on how
   to use it.

 * **Secure service to service communication based on identities**: Modern
   distributed applications rely on technologies such as application containers
   to facilitate agility in deployment and scale out on demand. This results in
   a large number of application containers to be started in a short period of
   time. Typical container firewalls secure workloads by filtering on source IP
   addresses and destination ports. This concept requires the firewalls on all
   servers to be manipulated whenever a container is started anywhere in the
   cluster.

   In order to avoid this situation which limits scale, Cilium assigns a
   security identity to groups of application containers which share identical
   security polices. The identity is then associated with all network packets
   emitted by the application containers, allowing to validate the identity at
   the receiving node. Security identity management is performed using a
   key-value store.

 * **Secure access to and from external services:** Label based security is the
   tool of choice for cluster internal access control. In order to secure
   access to and from external services, traditional CIDR based security
   policies for both ingress and egress are supported. This allows to limit
   access to and from application containers to particular IP ranges.

 * **Simple Networking:** A simple flat Layer 3 network with the ability to
   span multiple clusters connects all application containers. IP allocation is
   kept simple by using host scope allocators. This means that each host can
   allocate IPs without any coordination between hosts.

   The following multi node networking models are supported:

   * **Overlay:** Encapsulation based virtual network spawning all hosts.
     Currently VXLAN and Geneve are baked in but all encapsulation formats
     supported by Linux can be enabled.

     When to use this mode: This mode has minimal infrastructure and
     integration requirements. It works on almost any network infrastructure as
     the only requirement is IP connectivity between hosts which is typically
     already given.

   * **Native Routing:** Use of the regular routing table of the Linux host.
     The network is required to be capable to route the IP addresses of the
     application containers.

     When to use this mode: This mode is for advanced users and requires some
     awareness of the underlying networking infrastructure. This mode works
     well with:

     - Native IPv6 networks
     - In conjunction with cloud network routers
     - If you are already running routing daemons

   Additional transport mechanisms will be supported in the future, see the
   [roadmap][roadmap].

 * **Load balancing:** Distributed load balancing for traffic between
   application containers and to external services. The loadbalancing is
   implemented using BPF using efficient hashtables allowing for almost
   unlimited scale and supports direct server return (DSR) if the loadbalancing
   operation is not performed on the source host.

 * **Monitoring and Troubleshooting:** The ability to gain visibility and to
   troubleshoot issues is fundamental to the operation of any distributed
   system. While we learned to love tools like `tcpdump` and `ping` and while
   they will always find a special place in our hearts, we strive to provide
   better tooling for troubleshooting. This includes tooling to provide:

   - Event monitoring with metadata: When a packet is dropped, the tool doesn't
     just report the source and destination IP of the packet, the tool provides
     the full label information of both the sender and receiving among a lot of
     other information.

   - Policy decision tracing: Why is a packet being dropped or a request
     rejected. The policy tracing framework allows to trace the policy decision
     process for both, running workloads and based on artbirary label
     definitions.

   - Metrics export via Prometheus: Key metrics are exported via Prometheus for
     integration with your existing dashboards.

 * **Integrations:**
    * Network plugin integrations: [CNI][cni], [libnetwork][libnetwork]
    * Container runtime events: [containerd][containerd]
    * Kubernetes: [NetworkPolicy][k8s_netpolicy], [Labels][k8s_labels], [Ingress][k8s_ingress], [Service][k8s_service]
    * Logging: syslog, [fluentd][fluentd]

## Getting Started

 * [Why Cilium?](http://docs.cilium.io/en/latest/intro/#why-cilium)
 * [Getting Started](http://docs.cilium.io/en/latest/gettingstarted/)
 * [Architecture and Concepts](http://docs.cilium.io/en/latest/concepts/)
 * [Installing Cilium](http://cilium.readthedocs.io/en/latest/install/)
 * [Frequently Asked Questions](https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue%20label%3Aquestion%20)
 * [Contributing](http://docs.cilium.io/en/latest/contributing)

## What is eBPF and XDP?

Berkeley Packet Filter (BPF) is a Linux kernel bytecode interpreter originally
introduced to filter network packets, e.g. for tcpdump and socket filters. The
BPF instruction set and surrounding architecture has recently been
significantly reworked with additional data structures such as hash tables and
arrays for keeping state as well as additional actions to support packet
mangling, forwarding, encapsulation, etc. Furthermore, a compiler back end for
LLVM allows for programs to be written in C and compiled into BPF instructions.
An in-kernel verifier ensures that BPF programs are safe to run and a JIT
compiler converts the BPF bytecode to CPU architecture specific instructions
for native execution efficiency. BPF programs can be run at various hooking
points in the kernel such as for incoming packets, outgoing packets, system
calls, kprobes, uprobes, tracepoints, etc.

BPF continues to evolve and gain additional capabilities with each new Linux
release. Cilium leverages BPF to perform core data path filtering, mangling,
monitoring and redirection, and requires BPF capabilities that are in any Linux
kernel version 4.8.0 or newer (the latest current stable Linux kernel is
4.10.x).

Many Linux distributions including CoreOS, Debian, Docker's LinuxKit, Fedora,
and Ubuntu already ship kernel versions >= 4.8.x. You can check your Linux
kernel version by running ``uname -a``. If you are not yet running a recent
enough kernel, check the Documentation of your Linux distribution on how to run
Linux kernel 4.9.x or later.

To read up on the necessary kernel versions to run the BPF runtime, see the
section [Prerequisites][prerequisites].

<p align="center">
   <img src="Documentation/images/bpf-overview.png"/>
</p>

XDP is a further step in evolution and enables to run a specific flavor of BPF
programs from the network driver with direct access to the packet's DMA buffer.
This is, by definition, the earliest possible point in the software stack,
where programs can be attached to in order to allow for a programmable, high
performance packet processor in the Linux kernel networking data path.

Further information about BPF and XDP targeted for developers can be found in
the [BPF and XDP reference guide][bpf-reference]

## Related Material

 * [k8s-snowflake](https://github.com/jessfraz/k8s-snowflake): Configs and
   scripts for bootstrapping an opinionated Kubernetes cluster anywhere using
   Cilium plugin.
 * [Using Cilium for NetworkPolicy][k8s-cilium-netpolicy]: Kubernetes
   documentation on how to use Cilium to implement NetworkPolicy.

## Presentations

 * DockerCon, April 18, 2017: [Cilium - Network and Application Security with BPF and XDP](https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp)
 * CNCF/KubeCon Meetup, March 28, 2017: [Linux Native, HTTP Aware Network Security](https://www.slideshare.net/ThomasGraf5/linux-native-http-aware-network-security)
 * Docker Distributed Systems Summit, Berlin, Oct 2016: [Slides](http://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823), [Video](https://www.youtube.com/watch?v=TnJF7ht3ZYc&list=PLkA60AVN3hh8oPas3cq2VA9xB7WazcIgs&index=7)
 * NetDev1.2, Tokyo, Sep 2016 - cls_bpf/eBPF updates since netdev 1.1: [Slides](http://borkmann.ch/talks/2016_tcws.pdf), [Video](https://youtu.be/gwzaKXWIelc?t=12m55s)
 * NetDev1.2, Tokyo, Sep 2016 - Advanced programmability and recent updates with tc’s cls_bpf: [Slides](http://borkmann.ch/talks/2016_netdev2.pdf), [Video](https://www.youtube.com/watch?v=GwT9hRiqdUo)
 * ContainerCon NA, Toronto, Aug 2016 - Fast IPv6 container networking with BPF & XDP: [Slides](http://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp)

## Podcasts

 * Software Gone Wild by Ivan Pepelnjak, Oct 2016: [Blog](http://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html), [MP3](http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3)
 * OVS Orbit by Ben Pfaff, May 2016: [Blog](https://ovsorbit.benpfaff.org/#e4), [MP3](https://ovsorbit.benpfaff.org/episode-4.mp3)

## Community blog posts

 * Cilium for Network and Application Security with BPF and XDP, Apr 2017:
   [Blog](https://blog.scottlowe.org/2017/04/18/black-belt-cilium/)
 * Cilium, BPF and XDP, Google Open Source Blog, Nov 2016:
   [Blog](https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html)

## Weekly Hangout
 * The developer community is hanging out on zoom on a weekly basis to chat. Everybody is welcome.
 * Weekly, Monday, 9:00 am PT, 12:00 pm (noon) ET, 6:00 pm CEST
 * [Join zoom](https://zoom.us/j/344163933)

## Contact

If you have any questions feel free to contact us on [Slack](https://cilium.herokuapp.com/)

## License

The cilium user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0](bpf/COPYING).

[prerequisites]: http://docs.cilium.io/en/latest/admin/#admin-kernel-version
[installation]: http://docs.cilium.io/en/latest/admin/#installing-cilium
[cni]: https://github.com/containernetworking/cni
[libnetwork]: https://github.com/docker/libnetwork
[containerd]: https://github.com/containerd/containerd
[k8s_service]: https://kubernetes.io/docs/concepts/services-networking/service/
[k8s_ingress]: https://kubernetes.io/docs/concepts/services-networking/ingress/
[k8s_netpolicy]: https://kubernetes.io/docs/concepts/services-networking/network-policies/
[k8s_labels]: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
[fluentd]: http://www.fluentd.org/
[roadmap]: http://docs.cilium.io/en/latest/roadmap/
[bpf-reference]: http://cilium.readthedocs.io/en/latest/bpf/
[l7-proto]: http://cilium.readthedocs.io/en/latest/policy/#layer-7
[k8s-cilium-netpolicy]: https://kubernetes.io/docs/tasks/administer-cluster/cilium-network-policy/
