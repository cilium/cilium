.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _standalone_dns_proxy:

***************************************
Standalone DNS Proxy (alpha)
***************************************

.. include:: ../../alpha.rst

The Standalone DNS Proxy is an independent component that runs as a separate
DaemonSet in the cluster, providing DNS proxying capabilities independent of
the Cilium agent. The in agent proxy runs alongside the Standalone DNS Proxy.
The load of DNS request is shared between both proxies.

.. note::

   The Standalone DNS Proxy is currently in alpha stage. It is recommended to test
   thoroughly before using in production environments.

Overview
========

The Standalone DNS Proxy communicates with the Cilium agent via gRPC to:

1. Receive DNS policy rules from the agent
2. Report DNS query results for policy enforcement to the agent

Configuration
=============

To enable the Standalone DNS Proxy, set the following Helm values:

.. code-block:: yaml

   standaloneDnsProxy:
     enabled: true
     proxyPort: 10094
     serverPort: 10095

.. important::

   The ``standaloneDnsProxy.proxyPort`` must match the ``dnsProxy.proxyPort`` 
   configuration in the Cilium agent. Both the agent and standalone DNS proxy 
   expect these ports to be the same for proper communication and DNS traffic 
   interception.

Testing the Standalone DNS Proxy
=================================

This section provides steps to test the Standalone DNS Proxy in a development environment.

Building and Deploying
-----------------------

1. **Build the Standalone DNS Proxy Image**

   Build the standalone DNS proxy container image:

   .. code-block:: shell-session

      $ make docker-standalone-dns-proxy-image

2. **Set Up kind Cluster with Cilium**

   Create a kind cluster and install Cilium:

   .. code-block:: shell-session

      $ make kind && make kind-image && make kind-install-cilium

3. **Load the Image into kind**

   Load the standalone DNS proxy image into the kind cluster:

   .. code-block:: shell-session

      $ kind load docker-image quay.io/cilium/standalone-dns-proxy:latest

4. **Upgrade Cilium to Enable Standalone DNS Proxy**

   Enable the standalone DNS proxy and configure it to work with the Cilium agent:

   .. code-block:: shell-session

      $ cilium upgrade \
          --chart-directory='./install/kubernetes/cilium' \
          --set='l7Proxy=true' \
          --set='dnsProxy.proxyPort=10094' \
          --helm-set='standaloneDnsProxy.enabled=true' \
          --helm-set='standaloneDnsProxy.proxyPort=10094' \
          --helm-set='standaloneDnsProxy.l7Proxy=true' \
          --helm-set='standaloneDnsProxy.image.repository=quay.io/cilium/standalone-dns-proxy' \
          --helm-set='standaloneDnsProxy.image.tag=latest' \
          --helm-set='standaloneDnsProxy.image.useDigest=false' \
          --helm-set='standaloneDnsProxy.image.pullPolicy=Never'

   .. note::

      * Both ``dnsProxy.proxyPort`` and ``standaloneDnsProxy.proxyPort`` are set to ``10094`` to ensure proper communication
      * ``l7Proxy=true`` enables L7 proxy support required for DNS policy enforcement
      * ``image.pullPolicy=Never`` is used for local testing with kind

5. **Restart Cilium Agent**

   Restart the Cilium agent to apply the configuration changes:

   .. code-block:: shell-session

      $ kubectl rollout restart ds -n kube-system cilium

6. **Verify Deployment**

   Check that the standalone DNS proxy pods are running:

   .. code-block:: shell-session

      $ kubectl -n kube-system get pods -l k8s-app=standalone-dns-proxy
      NAME                          READY   STATUS    RESTARTS   AGE
      standalone-dns-proxy-xxxxx    1/1     Running   0          1m

7. **Apply DNS Policy**

   Apply a policy that allows pods with the label ``org: alliance`` to query specific domains
   (``cilium.io`` and its subdomains) and blocks all other queries:

   .. literalinclude:: ../../../examples/policies/l7/dns/dns.yaml
      :language: yaml

   .. code-block:: shell-session

      $ kubectl apply -f examples/policies/l7/dns/dns.yaml

8. **Deploy Test Pod**

   Create a test pod with the matching label:

   .. code-block:: shell-session

      $ kubectl run test-pod --image=nicolaka/netshoot --labels="org=alliance" -- sleep 3600

9. **Verify DNS Policy Enforcement**

   Test that DNS queries are being intercepted and resolved for allowed domains:

   .. code-block:: shell-session

      $ kubectl exec test-pod -- nslookup cilium.io.

   Queries to ``cilium.io`` should succeed.

   Now test that queries to non-allowed domains are refused:

   .. code-block:: shell-session

      $ kubectl exec test-pod -- nslookup example.com.
      Server:         10.96.0.10
      Address:        10.96.0.10#53

      ** server can't find example.com: REFUSED

   The query to ``example.com`` is refused because it's not in the allowed DNS policy rules.

10. **Test Standalone Proxy Resilience**

    Verify that the standalone DNS proxy continues to work even when the Cilium agent is down:

    .. code-block:: shell-session

       # Intentionally break the Cilium agent by using a non-existent image
       $ kubectl set image -n kube-system ds/cilium cilium-agent=quay.io/cilium/cilium:non-existent-image
       
       # Wait for agent pods to enter ImagePullBackOff state
       $ kubectl wait --for=condition=Ready=false pod -n kube-system -l k8s-app=cilium --timeout=60s
       
       # DNS queries for allowed domains should still work via standalone DNS proxy
       $ kubectl exec test-pod -- nslookup cilium.io

       # Verify that policy enforcement still works - non-allowed domains are still refused
       $ kubectl exec test-pod -- nslookup example.com
       Server:         10.96.0.10
       Address:        10.96.0.10#53

       ** server can't find example.com: REFUSED

    Both queries demonstrate that the standalone DNS proxy continues to enforce DNS policies
    independently, allowing ``cilium.io`` and refusing ``example.com``, even when the agent is unavailable.

11. **Restore Cilium Agent**

    Restore the Cilium agent to normal operation:

    .. code-block:: shell-session

       $ kubectl rollout undo ds/cilium -n kube-system

For more information on DNS policies, see :ref:`DNS based`.

Limitations
===========

The Standalone DNS Proxy alpha release has the following known limitations:

* Proxy port and server ports needs to be the same between Cilium agent and standalone DNS proxy
  for proper communication. The ports are defined by the ``dnsProxy.proxyPort`` and 
  ``standaloneDnsProxy.proxyPort`` settings in the Helm chart.
* Metrics related to DNS are not supported yet. The metrics are currently
  only available from the in-agent DNS proxy.
* Standalone DNS proxy depends on cilium agent to read DNS policies, enforce them and 
  communicate via gRPC. If there are connectivity issues between the proxy and agent,
  DNS policy enforcement may be affected.

Troubleshooting
===============

Port Configuration Mismatch
----------------------------

If DNS queries are not being properly proxied, verify that the proxy ports match:

.. code-block:: shell-session

   $ kubectl -n kube-system get configmap cilium-config -o yaml | grep -E 'tofqdns-proxy-port'
   $ kubectl -n kube-system get configmap standalone-dns-proxy-config -o yaml | grep -E 'tofqdns-proxy-port'

Both ``dnsProxy.proxyPort`` and ``standaloneDnsProxy.proxyPort`` must be set to the 
same value (default: ``10094``). A mismatch will prevent proper DNS traffic interception.

gRPC Communication Issues
-------------------------

If there are communication issues between the proxy and agent, review agent logs for connection errors:

.. code-block:: shell-session

   $ kubectl -n kube-system logs -l k8s-app=cilium --tail=100 | grep -i "grpc"

API Reference
=============

For detailed API documentation, see :ref:`sdpapi_ref`.

Further Reading
===============

* :ref:`DNS based`
* :ref:`DNS Proxy`
