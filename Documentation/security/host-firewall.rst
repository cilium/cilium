.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _host_firewall:

*************
Host Firewall
*************

This document serves as an introduction to Cilium's host firewall, to enforce
security policies for Kubernetes nodes.

.. admonition:: Video
  :class: attention
  
  You can also watch a video of Cilium's host firewall in action on
  `eCHO Episode 40: Cilium Host Firewall <https://www.youtube.com/watch?v=GLLLcz398K0&t=288s>`__.

Enable the Host Firewall in Cilium
==================================

.. include:: /installation/k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

    helm install cilium |CHART_RELEASE|        \\
      --namespace kube-system                  \\
      --set hostFirewall.enabled=true          \\
      --set devices='{ethX,ethY}'

The ``devices`` flag refers to the network devices Cilium is configured on such
as ``eth0``. Omitting this option leads Cilium to auto-detect what interfaces
the host firewall applies to.

At this point, the Cilium-managed nodes are ready to enforce network policies.


Attach a Label to the Node
==========================

In this guide, we will apply host policies only to nodes with the label
``node-access=ssh``. We thus first need to attach that label to a node in the
cluster.

.. code-block:: shell-session

    $ export NODE_NAME=k8s1
    $ kubectl label node $NODE_NAME node-access=ssh
    node/k8s1 labeled


Enable Policy Audit Mode for the Host Endpoint
==============================================

`HostPolicies` enforce access control over connectivity to and from nodes.
Particular care must be taken to ensure that when host policies are imported,
Cilium does not block access to the nodes or break the cluster's normal
behavior (for example by blocking communication with ``kube-apiserver``).

To avoid such issues, we can switch the host firewall in audit mode, to
validate the impact of host policies before enforcing them. When Policy Audit
Mode is enabled, no network policy is enforced so this setting is *not
recommended for production deployment*.

.. code-block:: shell-session

    $ CILIUM_NAMESPACE=kube-system
    $ CILIUM_POD_NAME=$(kubectl -n $CILIUM_NAMESPACE get pods -l "k8s-app=cilium" -o jsonpath="{.items[?(@.spec.nodeName=='$NODE_NAME')].metadata.name}")
    $ HOST_EP_ID=$(kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium endpoint list -o jsonpath='{[?(@.status.identity.id==1)].id}')
    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium endpoint config $HOST_EP_ID PolicyAuditMode=Enabled
    Endpoint 3353 configuration updated successfully
    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium endpoint config $HOST_EP_ID | grep PolicyAuditMode
    PolicyAuditMode          Enabled


Apply a Host Network Policy
===========================

`HostPolicies` match on node labels using a :ref:`NodeSelector` to identify the
nodes to which the policy applies. The following policy applies to all nodes.
It allows communications from outside the cluster only for TCP/22 and for ICMP
echo requests. All communications from the cluster to the hosts are allowed.

Host policies don't apply to communications between pods or between pods and
the outside of the cluster, except if those pods are host-networking pods.

.. literalinclude:: ../../examples/policies/host/demo-host-policy.yaml

To apply this policy, run:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/policies/host/demo-host-policy.yaml
    ciliumclusterwidenetworkpolicy.cilium.io/demo-host-policy created

The host is represented as a special endpoint, with label ``reserved:host``, in
the output of command ``cilium endpoint list``. You can therefore inspect the
status of the policy using that command.

.. code-block:: shell-session

    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6                 IPv4           STATUS
               ENFORCEMENT        ENFORCEMENT
    266        Disabled           Disabled          104        k8s:io.cilium.k8s.policy.cluster=default          f00d::a0b:0:0:ef4e   10.16.172.63   ready
                                                               k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                               k8s:io.kubernetes.pod.namespace=kube-system
                                                               k8s:k8s-app=kube-dns
    1687       Disabled (Audit)   Disabled          1          k8s:node-access=ssh                                                                   ready
                                                               reserved:host
    3362       Disabled           Disabled          4          reserved:health                                   f00d::a0b:0:0:49cf   10.16.87.66    ready


Adjust the Host Policy to Your Environment
==========================================

As long as the host endpoint is running in audit mode, communications
disallowed by the policy won't be dropped. They will however be reported by
``cilium monitor`` as ``action audit``. The audit mode thus allows you to
adjust the host policy to your environment, to avoid unexpected connection
breakages.

.. code-block:: shell-session

    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium monitor -t policy-verdict --related-to $HOST_EP_ID
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 6, proto 1, ingress, action allow, match L3-Only, 192.168.60.12 -> 192.168.60.11 EchoRequest
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 6, proto 6, ingress, action allow, match L3-Only, 192.168.60.12:37278 -> 192.168.60.11:2379 tcp SYN
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 2, proto 6, ingress, action audit, match none, 10.0.2.2:47500 -> 10.0.2.15:6443 tcp SYN

For details on how to derive the network policies from the output of ``cilium
monitor``, please refer to `observe_policy_verdicts` and
`create_network_policy` in the `policy_verdicts` guide.

In particular, `Entities based` rules are convenient for example to allow
communication to entire classes of destinations, such as all remotes nodes
(``remote-node``) or the entire cluster (``cluster``).

.. warning::

    Make sure that none of the communications required to access the cluster or
    for the cluster to work properly are denied. They should appear as ``action
    allow``.



Disable Policy Audit Mode
=========================

Once you are confident all required communication to the host from outside the
cluster are allowed, you can disable policy audit mode to enforce the host
policy.

.. code-block:: shell-session

    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium endpoint config $HOST_EP_ID PolicyAuditMode=Disabled
    Endpoint 3353 configuration updated successfully

Ingress host policies should now appear as enforced:

.. code-block:: shell-session

    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6                 IPv4           STATUS
               ENFORCEMENT        ENFORCEMENT
    266        Disabled           Disabled          104        k8s:io.cilium.k8s.policy.cluster=default          f00d::a0b:0:0:ef4e   10.16.172.63   ready
                                                               k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                               k8s:io.kubernetes.pod.namespace=kube-system
                                                               k8s:k8s-app=kube-dns
    1687       Enabled            Disabled          1          k8s:node-access=ssh                                                                   ready
                                                               reserved:host
    3362       Disabled           Disabled          4          reserved:health                                   f00d::a0b:0:0:49cf   10.16.87.66    ready


Communications not explicitly allowed by the host policy will now be dropped:

.. code-block:: shell-session

    $ kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME -- cilium monitor -t policy-verdict --related-to $HOST_EP_ID
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 2, proto 6, ingress, action deny, match none, 10.0.2.2:49038 -> 10.0.2.15:21 tcp SYN


Clean Up
========

.. code-block:: shell-session

   $ kubectl delete ccnp demo-host-policy
   $ kubectl label node $NODE_NAME node-access-
