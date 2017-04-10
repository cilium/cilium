<img src="https://cdn.rawgit.com/cilium/cilium/master/Documentation/images/logo.svg" alt="Cilium Logo" width="350" />

[![Build Status](https://jenkins.cilium.io/job/cilium/job/cilium/job/master/badge/icon)](https://jenkins.cilium.io/job/cilium/job/cilium/job/master/)
[![Go Report Card](https://goreportcard.com/badge/github.com/cilium/cilium)](https://goreportcard.com/report/github.com/cilium/cilium)
[![GoDoc](https://godoc.org/github.com/cilium/cilium?status.svg)](https://godoc.org/github.com/cilium/cilium)
[![Read the Docs](https://readthedocs.org/projects/docs/badge/?version=latest)](http://cilium.readthedocs.io/en/latest/)
[![Apache licensed](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/cilium/cilium/blob/master/LICENSE)
[![GPL licensed](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/cilium/cilium/blob/master/bpf/COPYING)
[![Join the Cilium slack channel](https://cilium.herokuapp.com/badge.svg)](https://cilium.herokuapp.com/)

Cilium is open source software for providing and transparently securing the
network connectivity between application services deployed using Linux
container management platforms like Docker and Kubernetes.

At the foundation of Cilium is a new Linux kernel technology called eBPF, which
enables the dynamic insertion of BPF bytecode into the Linux kernel. Cilium
generates individual BPF programs for each container to provide networking,
security and visibility.

<p align="center">
   <img src="Documentation/images/cilium-arch.png" />
</p>

## Components:
  * **Cilium Daemon**: Agent written in Go. Generates & compiles the BPF
    programs, manages the BPF maps, and interacts with the local container
    runtime.
  * **BPF programs**:
    * **container**: Container connectivity & security policies
    * **netdev**: Integration with L3 networks (physical/virtual)
    * **overlay**: Integration with overlay networks (VXLAN, Geneve)
    * **load balancer**: Fast L3/L4 load balancer with direct server return.
  * **Integrations**
    * **networking frameworks**: CNI, libnetwork
    * **container runtimes**: Docker
    * **orchestration systems**: Kubernetes
    * **logging**: logstash
    * **monitoring**:

## Getting Started

 * [Why Cilium?](http://docs.cilium.io/en/latest/intro/#why-cilium)
 * [Getting Started Guide with Vagrant](http://docs.cilium.io/en/latest/gettingstarted/)
 * [Architecture](http://docs.cilium.io/en/latest/architecture/)
 * [Administrator Guide](http://docs.cilium.io/en/latest/admin/)
 * [Frequently Asked Questions](https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue%20label%3Aquestion%20)
 * [Contributing](http://docs.cilium.io/en/latest/contributing)

## What is eBPF and XDP?

Berkeley Packet Filter (BPF) is a Linux kernel bytecode interpreter originally
introduced to filter network packets, e.g. tcpdump and socket filters. It has
since been extended with additional data structures such as hashtable and
arrays as well as additional actions to support packet mangling, forwarding,
encapsulation, etc. An in-kernel verifier ensures that BPF programs are safe to
run and a JIT compiler converts the bytecode to CPU architecture specific
instructions for native execution efficiency. BPF programs can be run at
various hooking points in the kernel such as for incoming packets, outgoing
packets, system calls, kprobes, etc.

BPF continues to evolve and gain additional capabilities with each new Linux
release. Cilium leverages BPF to perform core datapath filtering, mangling,
monitoring and redirection, and requires BPF capabilities that are in any Linux
kernel version 4.8.0 or newer (the latest current stable Linux kernel is
4.10.x).

Linux distros that focus on being a container runtime (e.g., CoreOS, Fedora
Atomic) typically already have default kernels that are newer than 4.8, but
even recent versions of general purpose operating systems, with the exception
of Ubuntu 16.10, are unlikely to have a default kernel that is 4.8+. However,
such OSes should support installing and running an alternative kernel that is
4.8+.

For more detail on kernel versions, see: [Prerequisites](prerequisites)

<p align="center">
   <img src="Documentation/images/bpf-overview.png" width="508" />
</p>

XDP is a further step in evolution and enables to run a specific flavour of
BPF programs from the network driver with direct access to the packet's DMA
buffer.

## Prerequisites

The easiest way to meet the prerequisites is to use the provided vagrant box
which provides all prerequisites in a sandbox environment. Please see the
[vagrant guide](Documentation/vagrant.rst) for more details.

In order to meet the prerequisites for an installation outside of vagrant,
the following components must be installed in at least the version specified:

 * Linux kernel (http://www.kernel.org/)
    * Minimum: >= 4.8.0
    * Recommended: >= 4.9.17. Use of a 4.9.17 kernel or later will ensure
      compatibility with clang > 3.9.x
 * clang+LLVM >=3.7.1. Please note that in order to use clang 3.9.x, the
   kernel version requirement is >= 4.9.17
 * iproute2 >= 4.8.0: https://www.kernel.org/pub/linux/utils/net/iproute2/

Cilium will make use of later kernel versions if available. It will probe
for the availability of the functionality automatically. It is therefore
perfectly acceptable to use a distribution kernel which has the required
functionality backported.

## Installation

See the [Installation instructions](installation)

## Presentations

 * CNCF/KubeCon Meetup, March 28, 2017: [Linux Native, HTTP Aware Network Security](https://www.slideshare.net/ThomasGraf5/linux-native-http-aware-network-security)
 * Docker Distributed Systems Summit, Berlin, Oct 2016: [Slides](http://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823), [Video](https://www.youtube.com/watch?v=TnJF7ht3ZYc&list=PLkA60AVN3hh8oPas3cq2VA9xB7WazcIgs&index=7)
 * NetDev1.2, Tokyo, Sep 2016 - cls_bpf/eBPF updates since netdev 1.1: [Slides](http://borkmann.ch/talks/2016_tcws.pdf), [Video](https://youtu.be/gwzaKXWIelc?t=12m55s)
 * NetDev1.2, Tokyo, Sep 2016 - Advanced programmability and recent updates with tc’s cls_bpf: [Slides](http://borkmann.ch/talks/2016_netdev2.pdf), [Video](https://www.youtube.com/watch?v=GwT9hRiqdUo)
 * ContainerCon NA, Toronto, Aug 2016 - Fast IPv6 container networking with BPF & XDP: [Slides](http://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp)
 * NetDev1.1, Seville, Feb 2016 - On getting tc classifier fully programmable with cls_bpf: [Slides](http://borkmann.ch/talks/2016_netdev.pdf), [Video](https://www.youtube.com/watch?v=KHXxSN5vwHY)

## Podcasts

 * Software Gone Wild by Ivan Pepelnjak, Oct 2016: [Blog](http://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html), [MP3](http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3)
 * OVS Orbit by Ben Pfaff, May 2016: [Blog](https://ovsorbit.benpfaff.org/#e4), [MP3](https://ovsorbit.benpfaff.org/episode-4.mp3)

## Community blog posts

 * Cilium, BPF and XDP, Google Open Source Blog, Nov 2016:
   [Blog](https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html)

## Weekly Hangout
 * The developer community is hanging out on zoom on a weekly basis to chat. Everybody is welcome.
 * Weekly, Monday, 8am PT, 11am ET, 5pm CEST
 * [Join zoom](https://zoom.us/j/344163933)

## Contact

If you have any questions feel free to contact us on [Slack](https://cilium.herokuapp.com/)

## License

The cilium user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0](bpf/COPYING).

[prerequisites]: http://docs.cilium.io/en/latest/admin/#admin-kernel-version
[installation]: http://docs.cilium.io/en/latest/admin/#installing-cilium
