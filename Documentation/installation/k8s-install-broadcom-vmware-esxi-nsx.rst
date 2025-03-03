.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_broadcom_vmware_esxi_nsx:

******************************************
Installation on Broadcom VMware ESXI / NSX
******************************************

Cilium can be installed on VMware ESXI with or without NSX by using official image

Deploying Cilium on Broadcom VMware vSphere ESXi with or without NSX(-T)
========================================================================

Cilium can be deployed on VMware vSphere ESXi, with or without NSX(-T). However, there are known issues when using VXLAN as the encapsulation mode.

Known Issue: Pod Communication Failure Across Hosts
===================================================

When deploying Cilium with VXLAN encapsulation, inter-host pod communication may fail, except for ICMP (ping), which still functions.

To check if you are affected by this issue, you can run the following command inside a Cilium pod:

.. code-block:: shell-session

    kubectl exec -n kube-system <cilium-pod> -- cilium--health status --verbose

Alternatively, you can use ``k8s-cilium.sh`` to inspect the cluster state refer to the :ref:`troubleshooting_k8s`

Additionally, you might encounter the following error related to HTTP probes: ``context deadline exceeded (Client.Timeout exceeded while awaiting headers)``

.. code-block:: bash

    ==== detail from pod cilium-mvrb6 , on node alg-rke2-cilium-cp
    Probe time:   2025-03-12T16:55:02Z
    Nodes:
    alg-cilium-cp (localhost):
        Host connectivity to 10.44.144.20:
        ICMP to stack:   OK, RTT=640.959µs
        HTTP to agent:   OK, RTT=148.15µs
        Endpoint connectivity to 10.42.0.38:
        ICMP to stack:   OK, RTT=632.181µs
        HTTP to agent:   OK, RTT=295.409µs
    alg-cilium-wk1:
        Host connectivity to 10.44.144.21:
        ICMP to stack:   OK, RTT=764.463µs
        HTTP to agent:   OK, RTT=1.154573ms
        Endpoint connectivity to 10.42.4.211:
        ICMP to stack:   OK, RTT=765.081µs
        HTTP to agent:   Get "http://10.42.4.211:4240/hello": context deadline exceeded (Client.Timeout exceeded while awaiting headers)


Affected Environments
=====================

This issue has been observed in the following scenarios:

    Older versions of vSphere ESXi (Before 8)
    Deployments using NSX-T (versions 3 or 4) on ESXi 7 or 8

Root Cause
==========

The problem originates from a `bug in the VMXNET3 driver <https://knowledge.broadcom.com/external/article/324199/vm-vxlan-traffic-fails-on-a-host-prepare.html>`__ related to NIC offload support for VXLAN encapsulation. This is due to the use of an outdated standard port (8472) for VXLAN.

Workarounds
===========

**Workaround 1: Use GENEVE Encapsulation**

Switch from VXLAN to GENEVE encapsulation.

.. code-block:: shell-session

    cilium config set tunnel-protocol geneve 

**Workaround 2: Change the VXLAN Port**

Modify the VXLAN port to use the standard port or an alternative one.

.. code-block:: shell-session

    cilium config set tunnel-port 8423 

**Workaround 3: Disable NIC Offload for Encapsulated Packets**

On the virtual machine, disable NIC offload for encapsulated packets to mitigate the issue.

.. code-block:: shell-session

    /sbin/ethtool -K ens160 tx-udp_tnl-csum-segmentation off
    /sbin/ethtool -K ens160 tx-udp_tnl-segmentation off

You need to replace by the name (ens160) of your network interface

You need to make this persistence to reboot (using for example systemd)