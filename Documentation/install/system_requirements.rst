.. _admin_system_reqs:

*******************
System Requirements
*******************

Before installing Cilium. Please ensure that your system is meeting the minimal
requirements to run Cilium. Most modern Linux distributions will automatically
meet the requirements.

Summary
=======

When running Cilium using the container image ``cilium/cilium``, these are
the requirements your system has to fulfill:

- `Linux kernel`_ >= 4.8 (>= 4.9.17 LTS recommended)
- Key-Value store (see :ref:`req_kvstore` section for version details)

The following additional dependencies are **only** required if you choose
**not** to use the ``cilium/cilium`` container image and want to run Cilium as
a native process on your host:

- `clang+LLVM`_ >=3.7.1
- iproute2_ >= 4.8.0

Linux Distribution Compatibility Matrix
=======================================

The following table lists Linux distributions versions which are known to work
well with Cilium.

===================== ====================
Distribution          Minimal Version
===================== ====================
CoreOS_               stable (>= 1298.5.0)
Debian_               >= 9 Stretch
`Fedora Atomic/Core`_ >= 25
LinuxKit_             all
Ubuntu_               >= 16.04.2, >= 16.10
===================== ====================

.. _CoreOS: https://coreos.com/releases/
.. _Debian: https://wiki.debian.org/DebianStretch
.. _Fedora Atomic/Core: http://www.projectatomic.io/blog/2017/03/fedora_atomic_2week_2/
.. _LinuxKit: https://github.com/linuxkit/linuxkit/tree/master/kernel
.. _Ubuntu: https://wiki.ubuntu.com/YakketyYak/ReleaseNotes#Linux_kernel_4.8

.. note:: The above list is composed based on feedback by users, if you have
          good experience with a particular Linux distribution which is not
          listed below, please let us know by opening a GitHub issue or by
          creating a pull request to update this guide.


.. _admin_kernel_version:

Linux Kernel
============

Cilium leverages and builds on the kernel functionality BPF as well as various
subsystems which integrate with BPF. Therefore, all systems that will run a
Cilium agent are required to run the Linux kernel version 4.8.0 or later.

The 4.8.0 kernel is the minimal kernel version required, more recent kernels may
provide additional BPF functionality. Cilium will automatically detect
additional available functionality by probing for the functionality when the
agent starts.

In order for the BPF feature to be enabled properly, the following kernel
configuration options must be enabled. This is typically the case automatically
with distribution kernels. If an option provides the choice to build as module
or statically linked, then both choices are valid.

.. code:: bash

        CONFIG_BPF=y
        CONFIG_BPF_SYSCALL=y
        CONFIG_NET_CLS_BPF=y
        CONFIG_BPF_JIT=y
        CONFIG_NET_CLS_ACT=y
        CONFIG_NET_SCH_INGRESS=y
        CONFIG_CRYPTO_SHA1=y
        CONFIG_CRYPTO_USER_API_HASH=y

.. _req_kvstore:

Key-Value store
===============

Cilium uses a distributed Key-Value store to manage and distribute security
identities across all cluster nodes. The following Key-Value stores are
currently supported:

- etcd >= 3.1.0
- consul >= 0.6.4

See section :ref:`install_kvstore` for details on how to configure the
``cilium-agent`` to use a Key-Value store.

clang+LLVM
==========


.. note:: This requirement is only needed if you run ``cilium-agent`` natively.
          If you are using the Cilium container image ``cilium/cilium``,
          clang+LLVM is included in the container image.

LLVM is the compiler suite which Cilium uses to generate BPF bytecode before
loading the programs into the Linux kernel.  The minimal version of LLVM
installed on the system is >=3.7.1. The version of clang installed must be
compiled with the BPF backend enabled.

See http://releases.llvm.org/ for information on how to download and install
LLVM.  Be aware that in order to use clang 3.9.x, the kernel version
requirement is >= 4.9.17.

iproute2
========

.. note:: This requirement is only needed if you run ``cilium-agent`` natively.
          If you are using the Cilium container image ``cilium/cilium``,
          iproute2 is included in the container image.

iproute2 is a low level tool used to configure various networking related
subsystems of the Linux kernel. Cilium uses iproute2 to configure networking
and ``tc`` which is part of iproute2 to load BPF programs into the kernel.

The minimal version of iproute2_ installed must be >= 4.8.0. Please see
https://www.kernel.org/pub/linux/utils/net/iproute2/ for documentation on how
to install iproute2.
