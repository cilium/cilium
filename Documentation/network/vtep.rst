.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _enable_vtep:

***********************************************
VXLAN Tunnel Endpoint (VTEP) Integration (beta)
***********************************************

.. include:: ../beta.rst

The VTEP integration allows third party VTEP devices to send and receive traffic to
and from Cilium-managed pods directly using VXLAN. This allows for example external
load balancers like BIG-IP to load balance traffic to Cilium-managed pods using VXLAN.

This document explains how to enable VTEP support and configure Cilium with VTEP
endpoint IPs, CIDRs, and MAC addresses.


.. note::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
   information. If unsure, run ``cilium status`` and validate that Cilium is up
   and running. This guide also assumes VTEP devices has been configured with
   VTEP endpoint IP, VTEP CIDRs, VTEP MAC addresses (VTEP MAC). The VXLAN network
   identifier (VNI) *must* be configured as VNI ``2``, which represents traffic
   from the VTEP as the world identity. See :ref:`reserved_labels` for more details.

Enable VXLAN Tunnel Endpoint (VTEP) integration
===============================================

This feature is disabled by default. When enabling the VTEP integration, you must
specify the IPs, CIDR ranges and MACs for each VTEP device.

There are two ways to configure VTEP endpoints:

1. **CiliumVTEPConfig CRD** (Recommended): Allows dynamic configuration changes
   without restarting Cilium agents.
2. **ConfigMap/Helm values** (Deprecated): Static configuration that requires
   Cilium agent restarts for changes to take effect.

.. _vtep_crd_config:

Using CiliumVTEPConfig CRD (Recommended)
----------------------------------------

The ``CiliumVTEPConfig`` CRD allows you to configure VTEP endpoints dynamically.
Changes to the CRD are applied immediately without requiring Cilium agent restarts.

First, enable VTEP support via Helm:

.. cilium-helm-upgrade::
   :namespace: kube-system
   :extra-args: --reuse-values
   :set: vtep.enabled="true"

Then create a ``CiliumVTEPConfig`` resource:

.. code-block:: yaml

   apiVersion: cilium.io/v2
   kind: CiliumVTEPConfig
   metadata:
     name: default
   spec:
     cidrMask: "255.255.255.0"
     endpoints:
     - name: vtep-device-1
       tunnelEndpoint: "10.169.72.236"
       cidr: "10.1.1.0/24"
       mac: "82:36:4c:98:2e:56"
     - name: vtep-device-2
       tunnelEndpoint: "10.169.72.238"
       cidr: "10.1.2.0/24"
       mac: "82:36:4c:98:2e:58"

Apply the configuration:

.. code-block:: bash

   kubectl apply -f ciliumvtepconfig.yaml

You can verify the status:

.. code-block:: bash

   kubectl get ciliumvtepconfig default -o yaml

The status section shows whether endpoints are successfully synced to the BPF map.

.. _vtep_configmap_config:

Using ConfigMap/Helm (Deprecated)
---------------------------------

.. warning::

   ConfigMap-based VTEP configuration (``vtep-endpoint``, ``vtep-cidr``, ``vtep-mac``)
   is deprecated and will be removed in Cilium v1.18. Please migrate to the
   ``CiliumVTEPConfig`` CRD as described in :ref:`vtep_crd_config`.

.. tabs::

    .. group-tab:: Helm

        If you installed Cilium via ``helm install``, you may enable
        the VTEP support with the following command:

        .. cilium-helm-upgrade::
           :namespace: kube-system
           :extra-args: --reuse-values
           :set: vtep.enabled="true"
                 vtep.endpoint="10.169.72.236 10.169.72.238"
                 vtep.cidr="10.1.1.0/24   10.1.2.0/24"
                 vtep.mask="255.255.255.0"
                 vtep.mac="82:36:4c:98:2e:56 82:36:4c:98:2e:58"

    .. group-tab:: ConfigMap

       VTEP support can be enabled by setting the
       following options in the ``cilium-config`` ConfigMap:

       .. code-block:: yaml

          enable-vtep:   "true"
          vtep-endpoint: "10.169.72.236    10.169.72.238"
          vtep-cidr:     "10.1.1.0/24   10.1.2.0/24"
          vtep-mask:     "255.255.255.0"
          vtep-mac:      "82:36:4c:98:2e:56 82:36:4c:98:2e:58"

       Restart Cilium daemonset:

       .. code-block:: bash

          kubectl -n $CILIUM_NAMESPACE rollout restart ds/cilium

.. _vtep_migration:

Migration from ConfigMap to CRD
-------------------------------

To migrate from ConfigMap-based configuration to the CRD:

1. Create a ``CiliumVTEPConfig`` CRD with your existing endpoint configurations.

2. Apply the CRD:

   .. code-block:: bash

      kubectl apply -f ciliumvtepconfig.yaml

3. The CRD configuration takes effect immediately. Cilium will log a warning
   indicating that ConfigMap settings are being ignored in favor of the CRD.

4. Remove the deprecated settings from your ConfigMap or Helm values:

   - ``vtep-endpoint`` / ``vtep.endpoint``
   - ``vtep-cidr`` / ``vtep.cidr``
   - ``vtep-mac`` / ``vtep.mac``

5. Keep ``enable-vtep: "true"`` / ``vtep.enabled=true`` as this flag is still required.


How to test VXLAN Tunnel Endpoint (VTEP) Integration
====================================================

Start up a Linux VM with node network connectivity to Cilium node.
To configure the Linux VM, you will need to be ``root`` user or
run the commands below using ``sudo``.

::

     Test VTEP Integration

     Node IP: 10.169.72.233
    +--------------------------+            VM IP: 10.169.72.236
    |                          |            +------------------+
    | CiliumNode               |            |  Linux VM        |
    |                          |            |                  |
    |  +---------+             |            |                  |
    |  | busybox |             |            |                  |
    |  |         |           ens192<------>ens192              |
    |  +--eth0---+             |            |                  |
    |      |                   |            +-----vxlan2-------+
    |      |                   |
    |   lxcxxx                 |
    |      |                   |
    +------+-----cilium_vxlan--+

.. code-block:: bash

   # Create a vxlan device and set the MAC address.
   ip link add vxlan2 type vxlan id 2 dstport 8472 local 10.169.72.236 dev ens192
   ip link set dev vxlan2 address 82:36:4c:98:2e:56
   ip link set vxlan2 up
   # Configure the VTEP with IP 10.1.1.236 to handle CIDR 10.1.1.0/24.
   ip addr add 10.1.1.236/24 dev vxlan2
   # Assume Cilium podCIDR network is 10.0.0.0/16, add route to 10.0.0.0/16
   ip route add 10.0.0.0/16 dev vxlan2  proto kernel  scope link  src 10.1.1.236
   # Allow Linux VM to send ARP broadcast request to Cilium node for busybox pod
   # ARP resolution through vxlan2 device
   bridge fdb append 00:00:00:00:00:00 dst 10.169.72.233 dev vxlan2

If you are managing multiple VTEPs, follow the above process for each instance.
Once the VTEPs are configured, you can configure Cilium to use the MAC, IP and CIDR ranges that
you have configured on the VTEPs. Follow the instructions to :ref:`enable_vtep`.

To test the VTEP network connectivity:

.. code-block:: bash

   # ping Cilium-managed busybox pod IP 10.0.1.1 for example from Linux VM
   ping 10.0.1.1

Limitations
===========

* This feature does not work with ipsec encryption between Cilium managed pod and VTEPs.
