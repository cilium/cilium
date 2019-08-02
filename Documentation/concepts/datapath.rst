.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _concepts_datapath:

********
Datapath
********

.. _aws_eni_datapath:

AWS ENI
=======

The AWS ENI datapath is enabled when Cilium is run with the option
``--ipam=eni``. It is a special purpose datapath that is useful when running
Cilium in an AWS environment.

Advantages of the model
-----------------------

* Pods are assigned ENI IPs which are directly routable in the AWS VPC. This
  simplifies communication of pod traffic within VPCs and avoids the need for
  SNAT.

* Pod IPs are assigned a security group. The security groups for pods are
  configured per node which allows to create node pools and give different
  security group assignments to different pods. See section :ref:`ipam_eni` for
  more details.

Disadvantages of this model
---------------------------

* The number of ENI IPs is limited per instance. The limit depends on the EC2
  instance type. This can become a problem when attempting to run a larger
  number of pods on very small instance types.

* Allocation of ENIs and ENI IPs requires interaction with the EC2 API which is
  subject to rate limiting. This is primarily mitigated via the operator
  design, see section :ref:`ipam_eni` for more details.

Architecture
------------

Ingress
~~~~~~~

1. Traffic is received on one of the ENIs attached to the instance which is
   represented on the node as interface ``ethN``.

2. An IP routing rule ensures that traffic to all local pod IPs is done using
   the main routing table:

   .. code-block:: bash

       20:	from all to 192.168.105.44 lookup main

3. The main routing table contains an exact match route to steer traffic into a
   veth pair which is hooked into the pod:

   .. code-block:: bash

       192.168.105.44 dev lxc5a4def8d96c5

4. All traffic passing ``lxc5a4def8d96c5`` on the way into the pod is subject
   to Cilium's BPF program to enforce network policies, provide service reverse
   load-balancing, and visibility.

Egress
~~~~~~

1. The pod's network namespace contains a default route which points to the
   node's router IP via the veth pair which is named ``eth0`` inside of the pod
   and ``lxcXXXXXX`` in the host namespace. The router IP is allocated from the
   ENI space, allowing for sending of ICMP errors from the router IP for Path
   MTU purposes.

2. After passing through the veth pair and before reaching the Linux routing
   layer, all traffic is subject to Cilium's BPF program to enforce network
   policies, implement load-balancing and provide networking features.

3. An IP routing rule ensures that traffic from individual endpoints are using
   a routing table specific to the ENI from which the endpoint IP was
   allocated:

   .. code-block:: bash

       30:	from 192.168.105.44 to 192.168.0.0/16 lookup 92

4. The ENI specific routing table contains a default route which redirects
   to the router of the VPC via the ENI interface:

   .. code-block:: bash

       default via 192.168.0.1 dev eth2
       192.168.0.1 dev eth2


Configuration
-------------

The AWS ENI datapath is enabled by setting the following option:

.. code-block: yaml

        ipam: eni
        blacklist-conflicting-routes: "false"
        enable-endpoint-routes: "true"
        auto-create-cilium-node-resource: "true"
        egress-masquerade-interfaces: eth+

* ``ipam: eni`` Enables the ENI specific IPAM backend and indicates to the
  datapath that ENI IPs will be used.

* ``blacklist-conflicting-routes: "false"`` disables blacklisting of local
  routes. This is required as routes will exist covering ENI IPs pointing to
  interfaces that are not owned by Cilium. If blacklisting is not disabled, all
  ENI IPs would be considered used by another networking component.

* ``enable-endpoint-routes: "true"`` enables direct routing to the ENI
  veth pairs without requiring to route via the ``cilium_host`` interface.

* ``auto-create-cilium-node-resource: "true"`` enables the automatic creation of
  the ``CiliumNode`` custom resource with all required ENI parameters. It is
  possible to disable this and provide the custom resource manually.

* ``egress-masquerade-interfaces: eth+`` is the interface selector of all
  interfaces which are subject to masquerading. Masquerading can be disabled
  entirely with ``masquerade: "false"``.

See the section :ref:`ipam_eni` for details on how to configure ENI IPAM
specific parameters.

