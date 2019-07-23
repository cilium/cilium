.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

******************
Component Overview
******************

.. image:: ../images/cilium-arch.png
    :align: center

A deployment of Cilium consists of the following components running on each
Linux container node in the container cluster:

* **Cilium Agent (Daemon):** Userspace daemon that interacts with the container runtime
  and orchestration systems such as Kubernetes via Plugins to setup networking
  and security for containers running on the local server.  Provides an API for
  configuring network security policies, extracting network visibility data,
  etc.

* **Cilium CLI Client:** Simple CLI client for communicating with the local
  Cilium Agent, for example, to configure network security or visibility
  policies.

* **Linux Kernel BPF:** Integrated capability of the Linux kernel to accept
  compiled bytecode that is run at various hook / trace points within the kernel.
  Cilium compiles BPF programs and has the kernel run them at key points in the
  network stack to have visibility and control over all network traffic in /
  out of all containers.

* **Container Platform Network Plugin:**  Each container platform (e.g.,
  Docker, Kubernetes) has its own plugin model for how external networking
  platforms integrate.  In the case of Docker, each Linux node runs a process
  (cilium-docker) that handles each Docker libnetwork call and passes data /
  requests on to the main Cilium Agent.

In addition to these components, Cilium also depends on the following
components running in the cluster:

* **Key-Value Store:** Cilium shares data between Cilium Agents on different
  nodes via a kvstore. The currently supported key-value stores are etcd or
  consul.

* **Cilium Operator:** Daemon for handling cluster management duties which can
  be handled once per cluster, rather than once per node.

Cilium Agent
============

The Cilium agent (cilium-agent) runs on each Linux container host.  At a
high-level, the agent accepts configuration that describes service-level
network security and visibility policies.   It then listens to events in the
container runtime to learn when containers are started or stopped, and it
creates custom BPF programs which the Linux kernel uses to control all network
access in / out of those containers.  In more detail, the agent:

* Exposes APIs to allow operations / security teams to configure security
  policies (see below) that control all communication between containers in the
  cluster.  These APIs also expose monitoring capabilities to gain additional
  visibility into network forwarding and filtering behavior.

* Gathers metadata about each new container that is created.  In particular, it
  queries identity metadata like container / pod labels, which are used to
  identify `endpoints` in Cilium security policies.

* Interacts with the container platforms network plugin to perform IP address
  management (IPAM), which controls what IPv4 and IPv6 addresses are assigned
  to each container. The IPAM is managed by the agent in a shared pool between
  all plugins which means that the Docker and CNI network plugin can run side
  by side allocating a single address pool.

* Combines its knowledge about container identity and addresses with the
  already configured security and visibility policies to generate highly
  efficient BPF programs that are tailored to the network forwarding and
  security behavior appropriate for each container.

* Compiles the BPF programs to bytecode using `clang/LLVM
  <https://clang.llvm.org/>`_ and passes them to the Linux kernel to run for
  all packets in / out of the container's virtual ethernet device(s).


Cilium CLI Client
=================

The Cilium CLI Client (cilium) is a command-line tool that is installed along
with the Cilium Agent.  It gives a command-line interface to interact with all
aspects of the Cilium Agent API.   This includes inspecting Cilium's state
about each network endpoint (i.e., container), configuring and viewing security
policies, and configuring network monitoring behavior.

Linux Kernel BPF
================

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
release.  Cilium leverages BPF to perform core datapath filtering, mangling,
monitoring and redirection, and requires BPF capabilities that are in any Linux
kernel version 4.8.0 or newer. On the basis that 4.8.x is already declared end
of life and 4.9.x has been nominated as a stable release we recommend to run at
least kernel 4.9.17 (the latest current stable Linux kernel as of this writing
is 4.10.x).

Cilium is capable of probing the Linux kernel for available features and will
automatically make use of more recent features as they are detected.

Linux distros that focus on being a container runtime (e.g., CoreOS, Fedora
Atomic) typically already ship kernels that are newer than 4.8, but even recent
versions of general purpose operating systems such as Ubuntu 16.10 ship fairly
recent kernels. Some Linux distributions still ship older kernels but many of
them allow installing recent kernels from separate kernel package repositories.

For more detail on kernel versions, see: :ref:`admin_kernel_version`.

Key-Value Store
===============

The Key-Value (KV) Store is used for the following state:

* Policy Identities: list of labels <=> policy identity identifier

* Global Services: global service id to VIP association (optional)

* Encapsulation VTEP mapping (optional)

To simplify things in a larger deployment, the key-value store can be the same
one used by the container orchestrator (e.g., Kubernetes using etcd).

Cilium Operator
===============

The Cilium Operator is responsible for managing duties in the cluster which
should logically be handled once for the entire cluster, rather than once for
each node in the cluster. Its design helps with scale limitations in large
kubernetes clusters (>1000 nodes). The responsibilities of Cilium operator
include:

* Synchronizing kubernetes services with etcd for :ref:`Cluster Mesh`

* Synchronizing node resources with etcd

* Ensuring that DNS pods are managed by Cilium

* Garbage-collection of Cilium Endpoints resources, unused security identities
  from the key-value store, and status of deleted nodes from CiliumNetworkPolicy

* Translation of ``toGroups`` policy

* Interaction with the AWS API for managing :ref:`ipam_eni`

