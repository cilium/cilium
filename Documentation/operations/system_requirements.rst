.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

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

- Hosts with either AMD64 or AArch64 architecture
- `Linux kernel`_ >= 4.19.57 or equivalent (e.g., 4.18 on RHEL8)

When running Cilium as a native process on your host (i.e. **not** running the
``cilium/cilium`` container image) these additional requirements must be met:

- `clang+LLVM`_ >= 10.0
- iproute2_ with eBPF templating patches [#iproute2_foot]_

.. _`clang+LLVM`: https://llvm.org
.. _iproute2: https://www.kernel.org/pub/linux/utils/net/iproute2/

When running Cilium without Kubernetes these additional requirements
must be met:

- :ref:`req_kvstore` etcd >= 3.1.0

======================== ============================== ===================
Requirement              Minimum Version                In cilium container
======================== ============================== ===================
`Linux kernel`_          >= 4.19.57 or >= 4.18 on RHEL8 no
Key-Value store (etcd)   >= 3.1.0                       no
clang+LLVM               >= 10.0                        yes
iproute2                 >= 5.9.0 [#iproute2_foot]_     yes
======================== ============================== ===================

.. [#iproute2_foot] Requires support for eBPF templating as documented
   :ref:`below <iproute2_requirements>`.

Architecture Support
====================

Cilium images are built for the following platforms:

- AMD64
- AArch64

Linux Distribution Compatibility & Considerations
=================================================

The following table lists Linux distributions that are known to work
well with Cilium. Some distributions require a few initial tweaks. Please make
sure to read each distribution's specific notes below before attempting to
run Cilium.

========================== ====================
Distribution               Minimum Version
========================== ====================
`Amazon Linux 2`_          all
`Bottlerocket OS`_         all
`CentOS`_                  >= 8.0
`Container-Optimized OS`_  all
`CoreOS`_                  all
Debian_                    >= 10 Buster
Flatcar_                   all
LinuxKit_                  all
Opensuse_                  Tumbleweed, >=Leap 15.4
`RedHat Enterprise Linux`_ >= 8.0
Ubuntu_                    >= 18.04.3
========================== ====================

.. _Amazon Linux 2: https://aws.amazon.com/amazon-linux-2/
.. _CentOS: https://centos.org
.. _Container-Optimized OS: https://cloud.google.com/container-optimized-os/docs
.. _CoreOS: https://getfedora.org/coreos?stream=stable
.. _Debian: https://wiki.debian.org/DebianStretch
.. _Flatcar: https://www.flatcar-linux.org/
.. _LinuxKit: https://github.com/linuxkit/linuxkit/tree/master/kernel
.. _RedHat Enterprise Linux: https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux
.. _Ubuntu: https://wiki.ubuntu.com/YakketyYak/ReleaseNotes#Linux_kernel_4.8
.. _Opensuse: https://www.opensuse.org/
.. _Bottlerocket OS: https://github.com/bottlerocket-os/bottlerocket

.. note:: The above list is based on feedback by users. If you find an unlisted
          Linux distribution that works well, please let us know by opening a
          GitHub issue or by creating a pull request that updates this guide.


systemd-based distributions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some distributions need to be configured not to manage "foreign" routes. This
is the case in Ubuntu 22.04, for example (see :gh-issue:`18706`). This can
usually be done by setting

.. code-block:: text

   ManageForeignRoutes=no
   ManageForeignRoutingPolicyRules=no

in ``/etc/systemd/networkd.conf``, but please refer to your distribution's
documentation for the right way to perform this override.


Flatcar
~~~~~~~

Flatcar is known to manipulate network interfaces created and managed by
Cilium. This is especially true in the official Flatcar image for AWS EKS, and
causes connectivity issues and potentially prevents the Cilium agent from
booting when Cilium is running in ENI mode. To avoid this, disable DHCP on
these interfaces and mark them as unmanaged by adding

.. code-block:: text

        [Match]
        Name=eth[1-9]*

        [Network]
        DHCP=no

        [Link]
        Unmanaged=yes

to ``/etc/systemd/network/01-no-dhcp.network`` and then

.. code-block:: shell-session

        systemctl daemon-reload
        systemctl restart systemd-networkd

Ubuntu 22.04 on Raspberry Pi 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before running Cilium on Ubuntu 22.04 on a Raspberry Pi, please make sure to install the following package:

.. code-block:: shell-session

        sudo apt install linux-modules-extra-raspi

.. _admin_kernel_version:

Linux Kernel
============

Base Requirements
~~~~~~~~~~~~~~~~~

Cilium leverages and builds on the kernel eBPF functionality as well as various
subsystems which integrate with eBPF. Therefore, host systems are required to
run a recent Linux kernel to run a Cilium agent. More recent kernels may
provide additional eBPF functionality that Cilium will automatically detect and
use on agent start. For this version of Cilium, it is recommended to use kernel
4.19.57 or later (or equivalent such as 4.18 on RHEL8). For a list of features
that require newer kernels, see :ref:`advanced_features`.

In order for the eBPF feature to be enabled properly, the following kernel
configuration options must be enabled. This is typically the case with
distribution kernels. When an option can be built as a module or statically
linked, either choice is valid.

::

        CONFIG_BPF=y
        CONFIG_BPF_SYSCALL=y
        CONFIG_NET_CLS_BPF=y
        CONFIG_BPF_JIT=y
        CONFIG_NET_CLS_ACT=y
        CONFIG_NET_SCH_INGRESS=y
        CONFIG_CRYPTO_SHA1=y
        CONFIG_CRYPTO_USER_API_HASH=y
        CONFIG_CGROUPS=y
        CONFIG_CGROUP_BPF=y
        CONFIG_PERF_EVENTS=y


Requirements for Iptables-based Masquerading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are not using BPF for masquerading (``enable-bpf-masquerade=false``, the
default value), then you will need the following kernel configuration options.

::

        CONFIG_NETFILTER_XT_SET=m
        CONFIG_IP_SET=m
        CONFIG_IP_SET_HASH_IP=m

Requirements for L7 and FQDN Policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

L7 proxy redirection currently uses ``TPROXY`` iptables actions as well
as ``socket`` matches. For L7 redirection to work as intended kernel
configuration must include the following modules:

::

        CONFIG_NETFILTER_XT_TARGET_TPROXY=m
        CONFIG_NETFILTER_XT_TARGET_CT=m
        CONFIG_NETFILTER_XT_MATCH_MARK=m
        CONFIG_NETFILTER_XT_MATCH_SOCKET=m

When ``xt_socket`` kernel module is missing the forwarding of
redirected L7 traffic does not work in non-tunneled datapath
modes. Since some notable kernels (e.g., COS) are shipping without
``xt_socket`` module, Cilium implements a fallback compatibility mode
to allow L7 policies and visibility to be used with those
kernels. Currently this fallback disables ``ip_early_demux`` kernel
feature in non-tunneled datapath modes, which may decrease system
networking performance. This guarantees HTTP and Kafka redirection
works as intended.  However, if HTTP or Kafka enforcement policies or
visibility annotations are never used, this behavior can be turned off
by adding the following to the helm configuration command line:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     ...
     --set enableXTSocketFallback=false

.. _features_kernel_matrix:

Requirements for IPsec
~~~~~~~~~~~~~~~~~~~~~~

The :ref:`encryption_ipsec` feature requires a lot of kernel configuration
options, most of which to enable the actual encryption. Note that the
specific options required depend on the algorithm. The list below
corresponds to requirements for GCM-128-AES.

::

        CONFIG_XFRM=y
        CONFIG_XFRM_OFFLOAD=y
        CONFIG_XFRM_STATISTICS=y
        CONFIG_XFRM_ALGO=m
        CONFIG_XFRM_USER=m
        CONFIG_INET{,6}_ESP=m
        CONFIG_INET{,6}_IPCOMP=m
        CONFIG_INET{,6}_XFRM_TUNNEL=m
        CONFIG_INET{,6}_TUNNEL=m
        CONFIG_INET_XFRM_MODE_TUNNEL=m
        CONFIG_CRYPTO_AEAD=m
        CONFIG_CRYPTO_AEAD2=m
        CONFIG_CRYPTO_GCM=m
        CONFIG_CRYPTO_SEQIV=m
        CONFIG_CRYPTO_CBC=m
        CONFIG_CRYPTO_HMAC=m
        CONFIG_CRYPTO_SHA256=m
        CONFIG_CRYPTO_AES=m

Requirements for the Bandwidth Manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :ref:`bandwidth-manager` requires the following kernel configuration option
to change the packet scheduling algorithm.

::

        CONFIG_NET_SCH_FQ=m

.. _advanced_features:

Required Kernel Versions for Advanced Features
==============================================

Additional kernel features continues to progress in the Linux community. Some
of Cilium's features are dependent on newer kernel versions and are thus
enabled by upgrading to more recent kernel versions as detailed below.

====================================================== ===============================
Cilium Feature                                         Minimum Kernel Version
====================================================== ===============================
:ref:`bandwidth-manager`                               >= 5.1
:ref:`egress-gateway`                                  >= 5.2
VXLAN Tunnel Endpoint (VTEP) Integration               >= 5.2
:ref:`encryption_wg`                                   >= 5.6
Full support for :ref:`session-affinity`               >= 5.7
BPF-based proxy redirection                            >= 5.7
Socket-level LB bypass in pod netns                    >= 5.7
L3 devices                                             >= 5.8
BPF-based host routing                                 >= 5.10
IPv6 BIG TCP support                                   >= 5.19
====================================================== ===============================

.. _req_kvstore:

Key-Value store
===============

Cilium optionally uses a distributed Key-Value store to manage,
synchronize and distribute security identities across all cluster
nodes. The following Key-Value stores are currently supported:

- etcd >= 3.1.0

Cilium can be used without a Key-Value store when CRD-based state
management is used with Kubernetes. This is the default for new Cilium
installations. Larger clusters will perform better with a Key-Value
store backed identity management instead, see :ref:`k8s_quick_install`
for more details.

See :ref:`install_kvstore` for details on how to configure the
``cilium-agent`` to use a Key-Value store.

clang+LLVM
==========


.. note:: This requirement is only needed if you run ``cilium-agent`` natively.
          If you are using the Cilium container image ``cilium/cilium``,
          clang+LLVM is included in the container image.

LLVM is the compiler suite that Cilium uses to generate eBPF bytecode programs
to be loaded into the Linux kernel. The minimum supported version of LLVM
available to ``cilium-agent`` should be >=5.0. The version of clang installed
must be compiled with the eBPF backend enabled.

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
and ``tc``, which is part of iproute2, to load eBPF programs into the kernel.

The version of iproute2 must include the eBPF templating patches. Also, it
depends on Cilium's libbpf fork. See `Cilium iproute2 source`_ for more details.

.. _`Cilium iproute2 source`: https://github.com/cilium/iproute2/

.. _firewall_requirements:

Firewall Rules
==============

If you are running Cilium in an environment that requires firewall rules to enable connectivity, you will have to add the following rules to ensure Cilium works properly.

It is recommended but optional that all nodes running Cilium in a given cluster must be able to ping each other so ``cilium-health`` can report and monitor connectivity among nodes. This requires ICMP Type 0/8, Code 0 open among all nodes. TCP 4240 should also be open among all nodes for ``cilium-health`` monitoring. Note that it is also an option to only use one of these two methods to enable health monitoring. If the firewall does not permit either of these methods, Cilium will still operate fine but will not be able to provide health information.

For IPSec enabled Cilium deployments, you need to ensure that the firewall allows ESP traffic through. For example, AWS Security Groups doesn't allow ESP traffic by default.

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

The following ports should also be available on each node:

======================== ==================================================================
Port Range / Protocol    Description
======================== ==================================================================
4240/tcp                 cluster health checks (``cilium-health``)
4244/tcp                 Hubble server
4245/tcp                 Hubble Relay
4250/tcp                 mTLS port
4251/tcp                 Spire Agent health check port (listening on 127.0.0.1 or ::1)
6060/tcp                 cilium-agent pprof server (listening on 127.0.0.1)
6061/tcp                 cilium-operator pprof server (listening on 127.0.0.1)
6062/tcp                 Hubble Relay pprof server (listening on 127.0.0.1)
9878/tcp                 cilium-envoy health listener (listening on 127.0.0.1)
9879/tcp                 cilium-agent health status API (listening on 127.0.0.1 and/or ::1)
9890/tcp                 cilium-agent gops server (listening on 127.0.0.1)
9891/tcp                 operator gops server (listening on 127.0.0.1)
9892/tcp                 clustermesh-apiserver gops server (listening on 127.0.0.1)
9893/tcp                 Hubble Relay gops server (listening on 127.0.0.1)
9962/tcp                 cilium-agent Prometheus metrics
9963/tcp                 cilium-operator Prometheus metrics
9964/tcp                 cilium-envoy Prometheus metrics
51871/udp                WireGuard encryption tunnel endpoint
======================== ==================================================================

.. _admin_mount_bpffs:

Mounted eBPF filesystem
=======================

.. Note::

        Some distributions mount the bpf filesystem automatically. Check if the
        bpf filesystem is mounted by running the command.

        .. code-block:: shell-session

            # mount | grep /sys/fs/bpf
            $ # if present should output, e.g. "none on /sys/fs/bpf type bpf"...

If the eBPF filesystem is not mounted in the host filesystem, Cilium will
automatically mount the filesystem.

Mounting this BPF filesystem allows the ``cilium-agent`` to persist eBPF
resources across restarts of the agent so that the datapath can continue to
operate while the agent is subsequently restarted or upgraded.

Optionally it is also possible to mount the eBPF filesystem before Cilium is
deployed in the cluster, the following command must be run in the host mount
namespace. The command must only be run once during the boot process of the
machine.

   .. code-block:: shell-session

	# mount bpffs /sys/fs/bpf -t bpf

A portable way to achieve this with persistence is to add the following line to
``/etc/fstab`` and then run ``mount /sys/fs/bpf``. This will cause the
filesystem to be automatically mounted when the node boots.

::

     bpffs			/sys/fs/bpf		bpf	defaults 0 0

If you are using systemd to manage the kubelet, see the section
:ref:`bpffs_systemd`.

Privileges
==========

The following privileges are required to run Cilium. When running the standard
Kubernetes :term:`DaemonSet`, the privileges are automatically granted to Cilium.

* Cilium interacts with the Linux kernel to install eBPF program which will then
  perform networking tasks and implement security rules. In order to install
  eBPF programs system-wide, ``CAP_SYS_ADMIN`` privileges are required. These
  privileges must be granted to ``cilium-agent``.

  The quickest way to meet the requirement is to run ``cilium-agent`` as root
  and/or as privileged container.

* Cilium requires access to the host networking namespace. For this purpose,
  the Cilium pod is scheduled to run in the host networking namespace directly.
