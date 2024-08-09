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

The ``devices`` flag refers to the network devices Cilium is configured on,
such as ``eth0``. If you omit this option, Cilium auto-detects what interfaces
the host firewall applies to. The resulting interfaces are shown in the
output of the ``cilium-dbg status`` command:

.. code-block:: shell-session

    $ kubectl exec -n kube-system ds/cilium -- \
         cilium-dbg status | grep 'Host firewall'

At this point, the Cilium-managed nodes are ready to enforce network policies.


Attach a Label to the Node
==========================

In this guide, host policies only apply to nodes with the label
``node-access=ssh``. Therefore, you first need to attach this label to a node
in the cluster:

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

To avoid such issues, switch the host firewall in audit mode and validate the
impact of host policies before enforcing them.

.. warning::

   When Policy Audit Mode is enabled, no network policy is enforced so this
   setting is not recommended for production deployment.

Enable and check status for the Policy Audit Mode on the host endpoint for a
given node with the following commands:

.. code-block:: shell-session

    $ CILIUM_NAMESPACE=kube-system
    $ CILIUM_POD_NAME=$(kubectl -n $CILIUM_NAMESPACE get pods -l "k8s-app=cilium" -o jsonpath="{.items[?(@.spec.nodeName=='$NODE_NAME')].metadata.name}")
    $ alias kexec="kubectl -n $CILIUM_NAMESPACE exec $CILIUM_POD_NAME --"
    $ HOST_EP_ID=$(kexec cilium-dbg endpoint list -o jsonpath='{[?(@.status.identity.id==1)].id}')
    $ kexec cilium-dbg status | grep 'Host firewall'
    Host firewall:           Enabled   [eth0]
    $ kexec cilium-dbg endpoint config $HOST_EP_ID PolicyAuditMode=Enabled
    Endpoint 3353 configuration updated successfully
    $ kexec cilium-dbg endpoint config $HOST_EP_ID | grep PolicyAuditMode
    PolicyAuditMode        : Enabled


Apply a Host Network Policy
===========================

:ref:`HostPolicies` match on node labels using a :ref:`NodeSelector` to
identify the nodes to which the policies applies. They apply only to the host
namespace, including host-networking pods. They don't apply to communications
between pods or between pods and the outside of the cluster, except if those
pods are host-networking pods.

The following policy applies to all nodes with the ``node-access=ssh`` label.
It allows communications from outside the cluster only for TCP/22 and for ICMP
(ping) echo requests. All communications from the cluster to the hosts are
allowed.

.. literalinclude:: ../../examples/policies/host/demo-host-policy.yaml

To apply this policy, run:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/policies/host/demo-host-policy.yaml
    ciliumclusterwidenetworkpolicy.cilium.io/demo-host-policy created

The host is represented as a special endpoint, with label ``reserved:host``, in
the output of command ``cilium-dbg endpoint list``. Use this command to inspect
the status of host policies:

.. code-block:: shell-session

    $ kexec cilium-dbg endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6                 IPv4           STATUS
               ENFORCEMENT        ENFORCEMENT
    266        Disabled           Disabled          104        k8s:io.cilium.k8s.policy.cluster=default          f00d::a0b:0:0:ef4e   10.16.172.63   ready
                                                               k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                               k8s:io.kubernetes.pod.namespace=kube-system
                                                               k8s:k8s-app=kube-dns
    1687       Disabled (Audit)   Disabled          1          k8s:node-access=ssh                                                                   ready
                                                               reserved:host
    3362       Disabled           Disabled          4          reserved:health                                   f00d::a0b:0:0:49cf   10.16.87.66    ready

In this example, one can observe that policy enforcement on the host endpoint
is in audit mode for ingress traffic, and disabled for egress traffic.


Adjust the Host Policy to Your Environment
==========================================

As long as the host endpoint runs in audit mode, communications disallowed by
the policy are not dropped. Nevertheless, they are reported by ``cilium-dbg
monitor``, as ``action audit``. With these reports, the audit mode allows you
to adjust the host policy to your environment in order to avoid unexpected
connection breakages.

.. code-block:: shell-session

    $ kexec cilium-dbg monitor -t policy-verdict --related-to $HOST_EP_ID
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 6, proto 1, ingress, action allow, match L3-Only, 192.168.60.12 -> 192.168.60.11 EchoRequest
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 6, proto 6, ingress, action allow, match L3-Only, 192.168.60.12:37278 -> 192.168.60.11:2379 tcp SYN
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 2, proto 6, ingress, action audit, match none, 10.0.2.2:47500 -> 10.0.2.15:6443 tcp SYN

For details on deriving the network policies from the output of ``cilium
monitor``, refer to `observe_policy_verdicts` and `create_network_policy` in
the `policy_verdicts` guide.

Note that `Entities based` rules are convenient when combined with host
policies, for example to allow communication to entire classes of destinations,
such as all remotes nodes (``remote-node``) or the entire cluster
(``cluster``).

.. warning::

    Make sure that none of the communications required to access the cluster or
    for the cluster to work properly are denied. Ensure they all appear as
    ``action allow`` before disabling the audit mode.

.. _disable_policy_audit_mode:

Disable Policy Audit Mode
=========================

Once you are confident all required communications to the host from outside the
cluster are allowed, disable the policy audit mode to enforce the host policy:

.. code-block:: shell-session

    $ kexec cilium-dbg endpoint config $HOST_EP_ID PolicyAuditMode=Disabled
    Endpoint 3353 configuration updated successfully

Ingress host policies should now appear as enforced:

.. code-block:: shell-session

    $ kexec cilium-dbg endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6                 IPv4           STATUS
               ENFORCEMENT        ENFORCEMENT
    266        Disabled           Disabled          104        k8s:io.cilium.k8s.policy.cluster=default          f00d::a0b:0:0:ef4e   10.16.172.63   ready
                                                               k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                               k8s:io.kubernetes.pod.namespace=kube-system
                                                               k8s:k8s-app=kube-dns
    1687       Enabled            Disabled          1          k8s:node-access=ssh                                                                   ready
                                                               reserved:host
    3362       Disabled           Disabled          4          reserved:health                                   f00d::a0b:0:0:49cf   10.16.87.66    ready


Communications that are not explicitly allowed by the host policy are now
dropped:

.. code-block:: shell-session

    $ kexec cilium-dbg monitor -t policy-verdict --related-to $HOST_EP_ID
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 2, proto 6, ingress, action deny, match none, 10.0.2.2:49038 -> 10.0.2.15:21 tcp SYN


Clean up
========

.. code-block:: shell-session

   $ kubectl delete ccnp demo-host-policy
   $ kubectl label node $NODE_NAME node-access-

Further Reading
===============

Read the documentation on :ref:`HostPolicies` for additional details on how to
use the policies. In particular, refer to the :ref:`Troubleshooting Host
Policies <troubleshooting_host_policies>` subsection to understand how to debug
issues with Host Policies, or to the section on :ref:`Host Policies known
issues <host_policies_known_issues>` to understand the current limitations of
the feature.
