.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _policy_verdicts:

*******************************
Creating Policies from Verdicts
*******************************

Policy Audit Mode configures Cilium to allow all traffic while logging all
connections that would otherwise be dropped by network policies. Policy Audit
Mode may be configured for the entire daemon using ``--policy-audit-mode=true``
or for individual Cilium Endpoints. When Policy Audit Mode is enabled, no
network policy is enforced so this setting is **not recommended for production
deployment**. Policy Audit Mode supports auditing network policies implemented
at networks layers 3 and 4. This guide walks through the process of creating
policies using Policy Audit Mode.

.. include:: gsg_requirements.rst
.. include:: gsg_sw_demo.rst

Scale down the deathstar Deployment
===================================

In this guide we're going to scale down the deathstar Deployment in order to
simplify the next steps:

.. code-block:: shell-session

   $ kubectl scale --replicas=1 deployment deathstar
   deployment.apps/deathstar scaled

Enable Policy Audit Mode (Entire Daemon)
========================================

To observe policy audit messages for all endpoints managed by this Daemonset,
modify the Cilium ConfigMap and restart all daemons:

   .. tabs::

      .. group-tab:: Configure via kubectl

         .. code-block:: shell-session

            $ kubectl patch -n $CILIUM_NAMESPACE configmap cilium-config --type merge --patch '{"data":{"policy-audit-mode":"true"}}'
            configmap/cilium-config patched
            $ kubectl -n $CILIUM_NAMESPACE rollout restart ds/cilium
            daemonset.apps/cilium restarted
            $ kubectl -n $CILIUM_NAMESPACE rollout status ds/cilium
            Waiting for daemon set "cilium" rollout to finish: 0 of 1 updated pods are available...
            daemon set "cilium" successfully rolled out

      .. group-tab:: Helm Upgrade

         If you installed Cilium via ``helm install``, then you can use ``helm
         upgrade`` to enable Policy Audit Mode:

         .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace $CILIUM_NAMESPACE \\
                --reuse-values \\
                --set policyAuditMode=true


Enable Policy Audit Mode (Specific Endpoint)
============================================

Cilium can enable Policy Audit Mode for a specific endpoint. This may be helpful when enabling
Policy Audit Mode for the entire daemon is too broad. Enabling per endpoint will ensure other
endpoints managed by the same daemon are not impacted.

This approach is meant to be temporary.  **Restarting Cilium pod will reset the Policy Audit
Mode to match the daemon's configuration.**

Policy Audit Mode is enabled for a given endpoint by modifying the endpoint configuration via
the ``cilium`` tool on the endpoint's Kubernetes node. The steps include:

#. Determine the endpoint id on which Policy Audit Mode will be enabled.
#. Identify the Cilium pod running on the same Kubernetes node corresponding to the endpoint.
#. Using the Cilium pod above, modify the endpoint configuration by setting ``PolicyAuditMode=Enabled``.

The following shell commands perform these steps:

.. code-block:: shell-session

   $ PODNAME=$(kubectl get pods -l app.kubernetes.io/name=deathstar -o jsonpath='{.items[*].metadata.name}')
   $ NODENAME=$(kubectl get pod -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].spec.nodeName}")
   $ ENDPOINT=$(kubectl get cep -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].status.id}")
   $ CILIUM_POD=$(kubectl -n "$CILIUM_NAMESPACE" get pod --all-namespaces --field-selector spec.nodeName="$NODENAME" -lk8s-app=cilium -o jsonpath='{.items[*].metadata.name}')
   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       cilium endpoint config "$ENDPOINT" PolicyAuditMode=Enabled
    Endpoint 232 configuration updated successfully

We can check that Policy Audit Mode is enabled for this endpoint with

.. code-block:: shell-session

   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       cilium endpoint get "$ENDPOINT" -o jsonpath='{[*].spec.options.PolicyAuditMode}'
   Enabled

.. _observe_policy_verdicts:

Observe policy verdicts
=======================

In this example, we are tasked with applying security policy for the deathstar.
First, from the Cilium pod we need to monitor the notifications for policy
verdicts using the Hubble CLI. We'll be monitoring for inbound traffic towards
the deathstar to identify it and determine whether to extend the network policy
to allow that traffic.

Apply a default-deny policy:

.. literalinclude:: ../../examples/minikube/sw_deny_policy.yaml

CiliumNetworkPolicies match on pod labels using an ``endpointSelector`` to identify
the sources and destinations to which the policy applies. The above policy denies
traffic sent to any pods with label (``org=empire``). Due to the Policy Audit Mode
enabled above (either for the entire daemon, or for just the ``deathstar`` endpoint),
the traffic will not actually be denied but will instead trigger policy verdict
notifications.

To apply this policy, run:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/sw_deny_policy.yaml
    ciliumnetworkpolicy.cilium.io/empire-default-deny created

With the above policy, we will enable a default-deny posture on ingress to pods
with the label ``org=empire`` and enable the policy verdict notifications for
those pods. The same principle applies on egress as well.

Now let's send some traffic from the tiefighter to the deathstar:

.. code-block:: shell-session

    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

We can check the policy verdict from the Cilium Pod:

.. code-block:: shell-session

   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       hubble observe flows -t policy-verdict --last 1
   Feb  7 12:53:39.168: default/tiefighter:54134 (ID:31028) -> default/deathstar-6fb5694d48-5hmds:80 (ID:16530) policy-verdict:none AUDITED (TCP Flags: SYN)

In the above example, we can see that the Pod ``deathstar-6fb5694d48-5hmds`` has
received traffic from the ``tiefighter`` Pod which doesn't match the policy
(``policy-verdict:none AUDITED``).

.. _create_network_policy:

Create the Network Policy
=========================

We can get more information about the flow with

.. code-block:: shell-session

   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       hubble observe flows -t policy-verdict -o json --last 1

Given the above information, we now know the labels of the source and
destination Pods, the traffic direction, and the destination port. In this case,
we can see clearly that the source (i.e. the tiefighter Pod) is an empire
aircraft (as it has the ``org=empire`` label) so once we've determined that we
expect this traffic to arrive at the deathstar, we can form a policy to match
the traffic:

.. literalinclude:: ../../examples/minikube/sw_l3_l4_policy.yaml

To apply this L3/L4 policy, run:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/sw_l3_l4_policy.yaml
    ciliumnetworkpolicy.cilium.io/rule1 created

Now if we run the landing requests again,

.. code-block:: shell-session

    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

we can then observe that the traffic which was previously audited to be dropped
by the policy is reported as allowed:

.. code-block:: shell-session

   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       hubble observe flows -t policy-verdict --last 1
   ...
   Feb  7 13:06:45.130: default/tiefighter:59824 (ID:31028) -> default/deathstar-6fb5694d48-5hmds:80 (ID:16530) policy-verdict:L3-L4 ALLOWED (TCP Flags: SYN)

Now the policy verdict states that the traffic would be allowed:
``policy-verdict:L3-L4 ALLOWED``. Success!

Disable Policy Audit Mode (Entire Daemon)
=========================================

These steps should be repeated for each connection in the cluster to ensure
that the network policy allows all of the expected traffic. The final step
after deploying the policy is to disable Policy Audit Mode again:

   .. tabs::

      .. group-tab:: Configure via kubectl

         .. code-block:: shell-session

            $ kubectl patch -n $CILIUM_NAMESPACE configmap cilium-config --type merge --patch '{"data":{"policy-audit-mode":"false"}}'
            configmap/cilium-config patched
            $ kubectl -n $CILIUM_NAMESPACE rollout restart ds/cilium
            daemonset.apps/cilium restarted
            $ kubectl -n kube-system rollout status ds/cilium
            Waiting for daemon set "cilium" rollout to finish: 0 of 1 updated pods are available...
            daemon set "cilium" successfully rolled out

      .. group-tab:: Helm Upgrade

         .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace $CILIUM_NAMESPACE \\
                --reuse-values \\
                --set policyAuditMode=false


Disable Policy Audit Mode (Specific Endpoint)
=============================================

These steps are nearly identical to enabling Policy Audit Mode.

.. code-block:: shell-session

   $ PODNAME=$(kubectl get pods -l app.kubernetes.io/name=deathstar -o jsonpath='{.items[*].metadata.name}')
   $ NODENAME=$(kubectl get pod -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].spec.nodeName}")
   $ ENDPOINT=$(kubectl get cep -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].status.id}")
   $ CILIUM_POD=$(kubectl -n "$CILIUM_NAMESPACE" get pod --all-namespaces --field-selector spec.nodeName="$NODENAME" -lk8s-app=cilium -o jsonpath='{.items[*].metadata.name}')
   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       cilium endpoint config "$ENDPOINT" PolicyAuditMode=Disabled
    Endpoint 232 configuration updated successfully

Alternatively, **restarting the Cilium pod** will set the endpoint Policy Audit Mode to the daemon set configuration.


Verify Policy Audit Mode is Disabled
====================================

.. code-block:: shell-session

   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
       cilium endpoint get "$ENDPOINT" -o jsonpath='{[*].spec.options.PolicyAuditMode}'
   Disabled

Now if we run the landing requests again, only the *tiefighter* pods with the
label ``org=empire`` should succeed:

.. code-block:: shell-session

    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

And we can observe that the traffic was allowed by the policy:

.. code-block:: shell-session

    $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
        hubble observe flows -t policy-verdict --from-pod tiefighter --last 1
    Feb  7 13:34:26.112: default/tiefighter:37314 (ID:31028) -> default/deathstar-6fb5694d48-5hmds:80 (ID:16530) policy-verdict:L3-L4 ALLOWED (TCP Flags: SYN)


This works as expected. Now the same request from an *xwing* Pod should fail:

.. code-block:: shell-session

    $ kubectl exec xwing -- curl --connect-timeout 3 -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    command terminated with exit code 28

This curl request should timeout after three seconds, we can observe the policy
verdict with:

.. code-block:: shell-session

    $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- \
        hubble observe flows -t policy-verdict --from-pod xwing --last 1
    Feb  7 13:43:46.791: default/xwing:54842 (ID:22654) <> default/deathstar-6fb5694d48-5hmds:80 (ID:16530) policy-verdict:none DENIED (TCP Flags: SYN)


We hope you enjoyed the tutorial.  Feel free to play more with the setup,
follow the `gs_http` guide, and reach out to us on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_ with any questions!

Clean-up
========

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml
   $ kubectl delete cnp empire-default-deny rule1
