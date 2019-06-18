.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_system_reqs:

*******************
System Requirements
*******************

Before installing Cilium, please ensure that your system meets the minimum
requirements below. Most modern Linux distributions already do.

Summary
=======

When running Cilium using the container image ``cilium/cilium``, the host
system must meet these requirements:

- `Linux kernel`_ >= 4.9.17
- :ref:`req_kvstore` etcd >= 3.1.0 or consul >= 0.6.4

When running Cilium as a native process on your host (i.e. **not** running the
``cilium/cilium`` container image) these additional requirements must be met:

- `clang+LLVM`_ >=5.0 (Recommended: >=7.0)
- iproute2_ with BPF templating patches [#iproute2_foot]_

.. _`clang+LLVM`: https://llvm.org
.. _iproute2: https://www.kernel.org/pub/linux/utils/net/iproute2/

======================== ========================== ===================
Requirement              Minimum Version            In cilium container
======================== ========================== ===================
`Linux kernel`_          >= 4.9.17                  no
Key-Value store (etcd)   >= 3.1.0                   no
Key-Value store (consul) >= 0.6.4                   no
clang+LLVM               >= 5.0.0                   yes
iproute2                 >= 5.0.0 [#iproute2_foot]_ yes
======================== ========================== ===================

.. [#iproute2_foot] Requires support for BPF templating as documented
   :ref:`below <iproute2_requirements>`.

Linux Distribution Compatibility Matrix
=======================================

The following table lists Linux distributions that are known to work
well with Cilium.

===================== ====================
Distribution          Minimum Version
===================== ====================
CoreOS_               stable (>= 1298.5.0)
Debian_               >= 9 Stretch
`Fedora Atomic/Core`_ >= 25
LinuxKit_             all
Ubuntu_               >= 16.04.2, >= 16.10
Opensuse_             Tumbleweed, >=Leap 15.0
===================== ====================

.. _CoreOS: https://coreos.com/releases/
.. _Debian: https://wiki.debian.org/DebianStretch
.. _Fedora Atomic/Core: http://www.projectatomic.io/blog/2017/03/fedora_atomic_2week_2/
.. _LinuxKit: https://github.com/linuxkit/linuxkit/tree/master/kernel
.. _Ubuntu: https://wiki.ubuntu.com/YakketyYak/ReleaseNotes#Linux_kernel_4.8
.. _Opensuse: https://www.opensuse.org/

.. note:: The above list is based on feedback by users. If you find an unlisted
          Linux distribution that works well, please let us know by opening a
          GitHub issue or by creating a pull request that updates this guide.

.. _admin_kernel_version:

Linux Kernel
============

Cilium leverages and builds on the kernel BPF functionality as well as various
subsystems which integrate with BPF. Therefore, host systems are required to
run Linux kernel version 4.8.0 or later to run a Cilium agent. More recent
kernels may provide additional BPF functionality that Cilium will automatically
detect and use on agent start.

In order for the BPF feature to be enabled properly, the following kernel
configuration options must be enabled. This is typically the case  with
distribution kernels. When an option can be built as a module or statically
linked, either choice is valid.

.. code:: bash

        CONFIG_BPF=y
        CONFIG_BPF_SYSCALL=y
        CONFIG_NET_CLS_BPF=y
        CONFIG_BPF_JIT=y
        CONFIG_NET_CLS_ACT=y
        CONFIG_NET_SCH_INGRESS=y
        CONFIG_CRYPTO_SHA1=y
        CONFIG_CRYPTO_USER_API_HASH=y

.. note::

   Users running Linux 4.10 or earlier with Cilium CIDR policies may face
   :ref:`cidr_limitations`.

.. _req_kvstore:

Key-Value store
===============

Cilium uses a distributed Key-Value store to manage, synchronize and distribute
security identities across all cluster nodes. The following Key-Value stores
are currently supported:

- etcd >= 3.1.0
- consul >= 0.6.4

See :ref:`install_kvstore` for details on how to configure the
``cilium-agent`` to use a Key-Value store.

clang+LLVM
==========


.. note:: This requirement is only needed if you run ``cilium-agent`` natively.
          If you are using the Cilium container image ``cilium/cilium``,
          clang+LLVM is included in the container image.

LLVM is the compiler suite that Cilium uses to generate BPF bytecode programs
to be loaded into the Linux kernel. The minimum supported version of LLVM
available to ``cilium-agent`` should be >=5.0. The version of clang installed
must be compiled with the BPF backend enabled.

See https://releases.llvm.org/ for information on how to download and install
LLVM.

.. _iproute2_requirements:

iproute2
========

.. note:: iproute2 is only needed if you run ``cilium-agent`` directly on the
          host machine. iproute2 is included in the ``cilium/cilium`` container
          image.

iproute2_ is a low level tool used to configure various networking related
subsystems of the Linux kernel. Cilium uses iproute2 to configure networking
and ``tc``, which is part of iproute2, to load BPF programs into the kernel.

The version of iproute2 must include the BPF templating patches. See the
links in the table below for documentation on how to install the correct
version of iproute2 for your distribution.

================= =========================
Distribution      Link
================= =========================
Binary (OpenSUSE) `Open Build Service`_
Source            `Cilium iproute2 source`_
================= =========================

.. _`Open Build Service`: https://build.opensuse.org/package/show/security:netfilter/iproute2
.. _`Cilium iproute2 source`: https://github.com/cilium/iproute2/tree/static-data

Host Firewall Rules
===================

If you have iptables enabled on your system, the following must be allowed:

========= =======================================
Chain     Required policy
========= =======================================
FORWARD   Accept forwarding to and from PodIPs
========= =======================================

.. _firewall_requirements:

Network Firewall Rules
======================

If you are running Cilium in an environment that requires firewall rules to enable connectivity, you will have to add the following rules to ensure Cilium works properly.

It is recommended but optional that all nodes running Cilium in a given cluster must be able to ping each other so ``cilium-health`` can report and monitor connectivity among nodes. This requires ICMP Type 0/8, Code 0 open among all nodes. TCP 4240 should also be open among all nodes for ``cilium-health`` monitoring. Note that it is also an option to only use one of these two methods to enable health monitoring. If the firewall does not permit either of these methods, Cilium will still operate fine but will not be able to provide health information.

If you are using VXLAN overlay network mode, Cilium uses Linux's default VXLAN port 8472 over UDP, unless Linux has been configured otherwise. In this case, UDP 8472 must be open among all nodes to enable VXLAN overlay mode. The same applies to Geneve overlay network mode, except the port is UDP 6081.

If you are running in direct routing mode, your network must allow routing of pod IPs.

As an example, if you are running on AWS with VXLAN overlay networking, here is a minimum set of AWS Security Group (SG) rules. It assumes a separation between the SG on the master nodes, ``master-sg``, and the worker nodes, ``worker-sg``. It also assumes ``etcd`` is running on the master nodes.

Master Nodes (``master-sg``) Rules:

======================== =============== ==================== ===============
Port Range / Protocol    Ingress/Egress  Source/Destination   Description
======================== =============== ==================== ===============
2379-2380/tcp            ingress         ``worker-sg``        etcd access
8472/udp                 ingress         ``master-sg`` (self) VXLAN overlay
8472/udp                 ingress         ``worker-sg``        VXLAN overlay
4240/tcp                 ingress         ``master-sg`` (self) health checks
4240/tcp                 ingress         ``worker-sg``        health checks
ICMP 8/0                 ingress         ``master-sg`` (self) health checks
ICMP 8/0                 ingress         ``worker-sg``        health checks
8472/udp                 egress          ``master-sg`` (self) VXLAN overlay
8472/udp                 egress          ``worker-sg``        VXLAN overlay
4240/tcp                 egress          ``master-sg`` (self) health checks
4240/tcp                 egress          ``worker-sg``        health checks
ICMP 8/0                 egress          ``master-sg`` (self) health checks
ICMP 8/0                 egress          ``worker-sg``        health checks
======================== =============== ==================== ===============

Worker Nodes (``worker-sg``):

======================== =============== ==================== ===============
Port Range / Protocol    Ingress/Egress  Source/Destination   Description
======================== =============== ==================== ===============
8472/udp                 ingress         ``master-sg``        VXLAN overlay
8472/udp                 ingress         ``worker-sg`` (self) VXLAN overlay
4240/tcp                 ingress         ``master-sg``        health checks
4240/tcp                 ingress         ``worker-sg`` (self) health checks
ICMP 8/0                 ingress         ``master-sg``        health checks
ICMP 8/0                 ingress         ``worker-sg`` (self) health checks
8472/udp                 egress          ``master-sg``        VXLAN overlay
8472/udp                 egress          ``worker-sg`` (self) VXLAN overlay
4240/tcp                 egress          ``master-sg``        health checks
4240/tcp                 egress          ``worker-sg`` (self) health checks
ICMP 8/0                 egress          ``master-sg``        health checks
ICMP 8/0                 egress          ``worker-sg`` (self) health checks
2379-2380/tcp            egress          ``master-sg``        etcd access
======================== =============== ==================== ===============

.. note:: If you use a shared SG for the masters and workers, you can condense 
          these rules into ingress/egress to self. If you are using Direct 
          Routing mode, you can condense all rules into ingress/egress ANY 
          port/protocol to/from self.

Privileges
==========

The following privileges are required to run Cilium. When running the standard
Kubernetes `DaemonSet`, the privileges are automatically granted to Cilium.

* Cilium interacts with the Linux kernel to install BPF program which will then
  perform networking tasks and implement security rules. In order to install
  BPF programs system-wide, ``CAP_SYS_ADMIN`` privileges are required. These
  privileges must be granted to ``cilium-agent``.

  The quickest way to meet the requirement is to run ``cilium-agent`` as root
  and/or as privileged container.

* Cilium requires access to the host networking namespace. For this purpose,
  the Cilium pod is scheduled to run in the host networking namespace directly.
