.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_ipam_crd:

***************
CRD-Backed IPAM
***************

This is a quick tutorial walking through how to enable CRD-backed IPAM. The
purpose of this tutorial is to show how components are configured and resources
interact with each other to enable users to automate or extend on their own.

For more details, see the section :ref:`concepts_ipam_crd`

Enable CRD IPAM mode
====================

#. Setup Cilium for Kubernetes using any of the available guides.
#. Run Cilium with the ``--ipam=crd`` option or set ``ipam: crd`` in the
   ``cilium-config`` ConfigMap.
#. Restart Cilium. Cilium will automatically register the CRD if not available already

   ::

	  msg="Waiting for initial IP to become available in 'k8s1' custom resource" subsys=ipam

#. Validate that the CRD has been registered:

   .. code-block:: shell-session

	   $ kubectl get crds
	   NAME                              CREATED AT
	   [...]
	   ciliumnodes.cilium.io             2019-06-08T12:26:41Z

Create a CiliumNode CR
======================

#. Import the following custom resource to make IPs available in the Cilium agent.

   .. code-block:: yaml

           apiVersion: "cilium.io/v2"
           kind: CiliumNode
           metadata:
             name: "k8s1"
           spec:
             ipam:
               pool:
                 192.168.1.1: {}
                 192.168.1.2: {}
                 192.168.1.3: {}
                 192.168.1.4: {}

#. Validate that Cilium has started up correctly

   .. code-block:: shell-session

           $ cilium status --all-addresses
           KVStore:                Ok   etcd: 1/1 connected, has-quorum=true: https://192.168.60.11:2379 - 3.3.12 (Leader)
           [...]
           IPAM:                   IPv4: 2/4 allocated,
           Allocated addresses:
             192.168.1.1 (router)
             192.168.1.3 (health)

#. Validate the ``status.IPAM.used`` section:

   .. code-block:: shell-session

       $ kubectl get cn k8s1 -o yaml
       apiVersion: cilium.io/v2
       kind: CiliumNode
       metadata:
         name: k8s1
         [...]
       spec:
         ipam:
           pool:
             192.168.1.1: {}
             192.168.1.2: {}
             192.168.1.3: {}
             192.168.1.4: {}
       status:
         ipam:
           used:
             192.168.1.1:
               owner: router
             192.168.1.3:
               owner: health

.. note::

    At the moment only single IP addresses are allowed. CIDR's are not supported.
