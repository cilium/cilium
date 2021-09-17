.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _CiliumEndpointSlice:

******************
EndpointSlice CRD
******************

When managing pods in Kubernetes, Cilium will create a Custom Resource
Definition (CRD) of Kind :ref:`CiliumEndpoint<CiliumEndpoint>` (CEP) for each
pod managed by Cilium. If ``enable-cilium-endpoint-slice`` is enabled, then
Cilium will also create a CRD of Kind ``CiliumEndpointSlice`` (CES) that groups
a set of slim CEP objects with the same :ref:`security identity<arch_id_security>`
together into a single CES object and broadcast CES objects to communicate
identities to other agents instead of doing so via broadcasting CEP.
In most cases, this reduces load on the control plane and can sustain
larger-scaled cluster using the same master resource.

For example:

.. code-block:: shell-session

    $ kubectl get ciliumendpointslices --all-namespaces
    NAME                  AGE
    ces-548bnpgsf-56q9f   171m
    ces-dy4d8x6j2-qgc2z   171m
    ces-f6qfylrxh-84vxm   171m
    ces-k29rv92f5-qb4sw   171m
    ces-m9gs68csm-w2qg8   171m
