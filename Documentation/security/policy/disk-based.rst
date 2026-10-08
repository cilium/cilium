.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _disk_policies:

Disk based Cilium Network Policies
==================================

This functionality enables users to place network policy YAML files directly into
the node's filesystem, bypassing the need for definition via k8s CRD.
By setting the config field ``static-cnp-path``, users specify the directory from
which policies will be loaded. The Cilium agent then processes all policy YAML files
present in this directory, transforming them into rules that are incorporated into
the policy engine. Additionally, the Cilium agent monitors this directory for any
new policy YAML files as well as any updates or deletions, making corresponding
updates to the policy engine's rules. It is important to note that this feature
only supports CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy.

The directory that the Cilium agent needs to monitor should be mounted from the host
using volume mounts. For users deploying via Helm, this can be enabled via ``extraArgs``
and ``extraHostPathMounts`` as follows:

.. code-block:: yaml

   extraArgs:
   - --static-cnp-path=/policies
   extraHostPathMounts:
   - name: static-policies
     mountPath: /policies
     hostPath: /policies
     hostPathType: Directory

To determine whether a policy was established via Kubernetes CRD or directly from a directory,
execute the command ``cilium policy get`` and examine the source attribute within the policy.
In output, you could notice policies that have been sourced from a directory will have the
``source`` field set as ``directory``. Additionally, ``cilium endpoint get <endpoint_id>`` also have
fields to show the source of policy associated with that endpoint.

Previous limitations and known issues
-------------------------------------

For Cilium versions prior to 1.14 deny-policies for peers outside the cluster
sometimes did not work because of :gh-issue:`15198`.  Make sure that you are
using version 1.14 or later if you are relying on deny policies to manage
external traffic to your cluster.
