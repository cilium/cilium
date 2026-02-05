.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _HostPolicies:

Host Policies
=============

Host policies take the form of a :ref:`CiliumClusterwideNetworkPolicy` with a
:ref:`NodeSelector` instead of an :ref:`EndpointSelector`. Host policies can
have layer 3 and layer 4 rules on both ingress and egress. They can also have
layer 7 DNS rules, but no other kinds of layer 7 rules.

.. note::

    Host L7 DNS policies are a beta feature.
    Please provide feedback and file a GitHub issue if you experience any problems.

.. attention::

    Adding layer 7 DNS rules to a host policy enables :ref:`DNS based`
    host policies at the cost of making all host DNS requests go through
    the :ref:`DNS Proxy` provided in each Cilium agent.
    This includes DNS requests for kube-apiserver if it is configured as a FQDN
    (e.g. in managed Kubernetes clusters) by critical processes such as kubelet.
    This has important implications for the proper functioning of the node,
    because while Cilium agent is restarting, :ref:`DNS Proxy` is not available,
    and all DNS requests redirected to it will time out.

    - When upgrading Cilium agent image on a set of nodes, the new image must be
      :ref:`pre-pulled <pre_flight>`, because kubelet will not be able to contact
      the container registry after it stops the old Cilium agent pod.

    - If Kubernetes feature gate `KubeletEnsureSecretPulledImages`_ is enabled
      and kubelet is configured with `image credential providers`_ relying on
      remote authentication and authorization services (common in managed Kubernetes),
      image pull credentials verification policy must be configured in such a way
      that the Cilium agent image is exempted from image credential verification.
      Otherwise kubelet may be unable to verify image pull credentials for the new
      Cilium agent pod, and it will fail to start (rendering the node unusable)
      despite the new agent image having been pre-pulled.


.. _KubeletEnsureSecretPulledImages: https://kubernetes.io/docs/concepts/containers/images/#ensureimagepullcredentialverification
.. _image credential providers: https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider

Host policies apply to all the nodes selected by their :ref:`NodeSelector`. In
each selected node, they apply only to the host namespace, including
host-networking pods. They don't apply to communications between
non-host-networking pods and locations outside of the cluster.

Installation of Host Policies requires the addition of the following ``helm``
flags when installing Cilium:

* ``--set devices='{interface}'`` where ``interface`` refers to the network
  device Cilium is configured on, for example ``eth0``. If you omit this
  option, Cilium auto-detects what interface the host firewall applies to.
* ``--set hostFirewall.enabled=true``

As an example, the following policy allows ingress traffic for any node with
the label ``type=ingress-worker`` on TCP ports 22, 6443 (kube-apiserver), 2379
(etcd), and 4240 (health checks), as well as UDP port 8472 (VXLAN).

.. literalinclude:: ../../../examples/policies/host/lock-down-ingress.yaml
  :language: yaml

To reuse this policy, replace the ``port:`` values with ports used in your
environment.

In order to allow protocols such as VRRP and IGMP that don't have any transport-layer
ports, set ``--enable-extended-ip-protocols`` flag to true. By default, such traffic is
dropped with ``DROP_CT_UNKNOWN_PROTO`` error.

As an example, the following policy allows egress traffic on any node with
the label ``type=egress-worker`` on TCP ports 22, 6443/443 (kube-apiserver), 2379
(etcd), and 4240 (health checks), UDP port 8472 (VXLAN), and traffic with VRRP protocol.

.. literalinclude:: ../../../examples/policies/host/allow-extended-protocols.yaml
  :language: yaml

.. _troubleshooting_host_policies:

Troubleshooting Host Policies
-----------------------------

If you have troubles with Host Policies, try the following steps:

- Ensure the ``helm`` options listed in :ref:`the Host Policies description
  <HostPolicies>` were applied during installation.

- To verify that your policy has been accepted and applied by the Cilium agent,
  run ``kubectl get CiliumClusterwideNetworkPolicy -o yaml`` and make sure the
  policy is listed.

- If policies don't seem to be applied to your nodes, verify the
  ``nodeSelector`` is labeled correctly in your environment. In the example
  configuration, you can run ``kubectl get nodes -o
  custom-columns=NAME:.metadata.name,LABELS:.metadata.labels | grep
  type:ingress-worker`` to verify labels match the policy.

To troubleshoot policies for a given node, try the following steps. For all
steps, run ``cilium-dbg`` in the relevant namespace, on the Cilium agent pod
for the node, for example with:

.. code-block:: shell-session

   $ kubectl exec -n $CILIUM_NAMESPACE $CILIUM_POD_NAME -- cilium-dbg ...

Retrieve the endpoint ID for the host endpoint on the node with ``cilium-dbg
endpoint get -l reserved:host -o jsonpath='{[0].id}'``. Use this ID to replace
``$HOST_EP_ID`` in the next steps:

- If policies are applied, but not enforced for the node, check the status of
  the policy audit mode with ``cilium-dbg endpoint config $HOST_EP_ID | grep
  PolicyAuditMode``. If necessary, :ref:`disable the audit mode
  <disable_policy_audit_mode>`.

- Run ``cilium-dbg endpoint list``, and look for the host endpoint, with
  ``$HOST_EP_ID`` and the ``reserved:host`` label. Ensure that policy is
  enabled in the selected direction.

- Run ``cilium-dbg status list`` and check the devices listed in the ``Host
  firewall`` field. Verify that traffic actually reaches the listed devices.

- Use ``cilium-dbg monitor`` with ``--related-to $HOST_EP_ID`` to examine
  traffic for the host endpoint.

.. _host_policies_known_issues:

Host Policies known issues
--------------------------

- The first time Cilium enforces Host Policies in the cluster, it may drop
  reply traffic for legitimate connections that should be allowed by the
  policies in place. Connections should stabilize again after a few seconds.
  One workaround is to enable, disable, then re-enable Host Policies
  enforcement. For details, see :gh-issue:`25448`.

- In the context of ClusterMesh, the following combination of options is not
  supported:

  - Cilium operating in CRD mode (as opposed to KVstore mode),
  - Host Policies enabled,
  - tunneling enabled,
  - kube-proxy-replacement enabled, and
  - WireGuard enabled.

  This combination results in a failure to connect to the
  clustermesh-apiserver. For details, refer to :gh-issue:`31209`.

- Host Policies do not work on host WireGuard interfaces. For details, see
  :gh-issue:`17636`.

- When Host Policies are enabled, hosts drop traffic from layer-2 protocols
  that they consider as unknown, even if no Host Policies are loaded. For
  example, this affects LLC traffic (see :gh-issue:`17877`) or VRRP traffic
  (see :gh-issue:`18347`).

- When kube-proxy-replacement is disabled, or configured not to implement
  services for the native device (such as NodePort), hosts will enforce Host
  Policies on service addresses rather than the service endpoints. For details,
  refer to :gh-issue:`12545`.

- Host Firewall and thus Host Policies do not work together with IPsec.
  For details, refer to :gh-issue:`41854`.
