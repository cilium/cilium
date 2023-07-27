.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _policy_verdicts:

*******************************
Creating policies from verdicts
*******************************

Policy Audit Mode configures Cilium to allow all traffic while logging all
connections that would otherwise be dropped by policy. Policy Audit Mode may be
configured for the entire daemon using ``--policy-audit-mode=true`` or for
individual Cilium Endpoints. When Policy Audit Mode is enabled, no network
policy is enforced so this setting is **not recommended for production
deployment**. Policy Audit Mode supports auditing network policies implemented
at networks layers 3 and 4. This guide walks through the process of creating
policies using Policy Audit Mode.

.. include:: gsg_requirements.rst
.. include:: gsg_sw_demo.rst

Enable Policy Audit Mode (Entire Daemon)
========================================

To observe policy audit messages for all endpoints managed by this daemonset, modify the Cilium configmap and restart all daemons:

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
#. Using the Cilium pod above, modify the endpoint config by setting ``PolicyAuditMode=Enabled``.

The following shell commands perform these steps:

.. code-block:: shell-session

   $ export PODNAME=deathstar
   $ export NODENAME=$(kubectl get pod -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].spec.nodeName}")
   $ export ENDPOINT=$(kubectl get cep -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].status.id}")
   $ export CILIUM_POD=$(kubectl -n "$CILIUM_NAMESPACE" get pod --all-namespaces --field-selector spec.nodeName="$NODENAME" -lk8s-app=cilium -o jsonpath='{.items[*].metadata.name}')
   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- cilium endpoint config "$ENDPOINT" PolicyAuditMode=Enabled
   Endpoint 232 configuration updated successfully


.. _observe_policy_verdicts:

Observe policy verdicts
=======================

In this example, we are tasked with applying security policy for the deathstar.
First, from the Cilium pod we need to monitor the notifications for policy
verdicts using ``cilium monitor -t policy-verdict``. We'll be monitoring for
inbound traffic towards the deathstar to identify that traffic and determine
whether to extend the network policy to allow that traffic.

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

With the above policy, we will enable default-deny posture on ingress to
pods with the label ``org=empire`` and enable the policy verdict
notifications for those pods. The same principle applies on egress as well.

From another terminal with kubectl access, send some traffic from the
tiefighter to the deathstar:

.. code-block:: shell-session

    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

Back in the Cilium pod, the policy verdict logs are printed in the monitor
output:

.. code-block:: shell-session

   # cilium monitor -t policy-verdict
   ...
   Policy verdict log: flow 0x63113709 local EP ID 232, remote ID 31028, proto 6, ingress, action audit, match none, 10.0.0.112 :54134 -> 10.29.50.40:80 tcp SYN

In the above example, we can see that endpoint ``232`` has received traffic
(``ingress true``) which doesn't match the policy (``action audit match
none``). The source of this traffic has the identity ``31028``. Let's gather a
bit more information about what these numbers mean:

.. code-block:: shell-session

   # cilium endpoint list
   ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                 IPv6                 IPv4            STATUS
              ENFORCEMENT        ENFORCEMENT
   232        Disabled (Audit)   Disabled          16530      k8s:class=deathstar                                                              10.29.50.40     ready
                                                              k8s:io.cilium.k8s.policy.cluster=default
                                                              k8s:io.cilium.k8s.policy.serviceaccount=default
                                                              k8s:io.kubernetes.pod.namespace=default
                                                              k8s:org=empire
   ...
   # cilium identity get 31028
   ID     LABELS
   31028  k8s:class=tiefighter
          k8s:io.cilium.k8s.policy.cluster=default
          k8s:io.cilium.k8s.policy.serviceaccount=default
          k8s:io.kubernetes.pod.namespace=default
          k8s:org=empire

.. _create_network_policy:

Create the Network Policy
=========================

Given the above information, we now know the labels of the target pod, the
labels of the peer that's attempting to connect, the direction of the traffic
and the port. In this case, we can see clearly that it's an empire craft
so once we've determined that we expect this traffic to arrive at the
deathstar, we can form a policy to match the traffic:

.. literalinclude:: ../../examples/minikube/sw_l3_l4_policy.yaml

To apply this L3/L4 policy, run:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/sw_l3_l4_policy.yaml
    ciliumnetworkpolicy.cilium.io/rule1 created

Now if we run the landing requests again, we can observe in the monitor output
that the traffic which was previously audited to be dropped by the policy are
now reported as allowed:

.. code-block:: shell-session

    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

Executed from the cilium pod:

.. code-block:: shell-session

   # cilium monitor -t policy-verdict
   Policy verdict log: flow 0xabf3bda6 local EP ID 232, remote ID 31028, proto 6, ingress, action allow, match L3-L4, 10.0.0.112 :59824 -> 10.0.0.147:80 tcp SYN

Now the policy verdict states that the traffic would be allowed: ``action
allow``. Success!

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

   $ export PODNAME=deathstar
   $ export NODENAME=$(kubectl get pod -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].spec.nodeName}")
   $ export ENDPOINT=$(kubectl get cep -o jsonpath="{.items[?(@.metadata.name=='$PODNAME')].status.id}")
   $ export CILIUM_POD=$(kubectl -n "$CILIUM_NAMESPACE" get pod --all-namespaces --field-selector spec.nodeName="$NODENAME" -lk8s-app=cilium -o jsonpath='{.items[*].metadata.name}')
   $ kubectl -n "$CILIUM_NAMESPACE" exec "$CILIUM_POD" -c cilium-agent -- cilium endpoint config "$ENDPOINT" PolicyAuditMode=Disabled
   Endpoint 232 configuration updated successfully

Alternatively, **restarting the Cilium pod** will set the endpoint Policy Audit Mode to the daemon set configuration.


Verify Policy Audit Mode Is Disabled
====================================

Now if we run the landing requests again, only the *tiefighter* pods with the
label ``org=empire`` will succeed. The *xwing* pods will be blocked!

.. code-block:: shell-session

    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

This works as expected. Now the same request run from an *xwing* pod will fail:

.. code-block:: shell-session

    $ kubectl exec xwing -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing

This request will hang, so press Control-C to kill the curl request, or wait
for it to time out.

We hope you enjoyed the tutorial.  Feel free to play more with the setup,
follow the `gs_http` guide, and reach out to us on `Cilium Slack`_ with any
questions!

Clean-up
========

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml
   $ kubectl delete cnp rule1
