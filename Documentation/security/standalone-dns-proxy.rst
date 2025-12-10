.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _standalone_dns_proxy:

***************************************
Standalone DNS Proxy (alpha)
***************************************

.. include:: ../alpha.rst

The Standalone DNS Proxy is an independent component that runs as a separate
DaemonSet in the cluster, providing DNS proxying capabilities independent of
the Cilium agent. The in-agent proxy runs alongside the Standalone DNS Proxy.
The load of DNS request is shared between both proxies.

Overview
========

The Standalone DNS Proxy communicates with the Cilium agent via gRPC to:

1. Receive DNS policy rules from the agent
2. Report DNS query results for policy enforcement to the agent

Configuration
=============

To enable the Standalone DNS Proxy, set the following Helm values:

.. code-block:: yaml

   # Enable L7 proxy and configure DNS proxy port
   l7Proxy: true
   dnsProxy:
     proxyPort: 10094  # Must be non-zero when using standalone DNS proxy, choosing 10094 as example
   
   # Enable standalone DNS proxy
   standaloneDnsProxy:
     enabled: true
     serverPort: 10095 # Must be non-zero when using standalone DNS proxy, choosing 10095 as example

.. important::

   The standalone DNS proxy uses the agent's DNS configuration to ensure consistency:
   
   * ``dnsProxy.proxyPort`` must be explicitly set to a non-zero value (e.g., 10094)
   * ``dnsProxy.enableDnsCompression`` and other DNS settings will automatically use 
     the same defaults as the agent (default: true)
   
   The Helm chart will fail validation if ``proxyPort`` is not configured correctly.

Testing the Standalone DNS Proxy
=================================

This section provides steps to test the Standalone DNS Proxy in a development environment.
To test the standalone DNS proxy feature, you need to build container images from
source. The following instructions guide you through building and deploying the 
standalone DNS proxy in a local development environment using kind (Kubernetes in Docker).

Building and Deploying
----------------------

#. **Build the Standalone DNS Proxy Image**

   Build the standalone DNS proxy container image from source:

   .. code-block:: shell-session

      $ make docker-standalone-dns-proxy-image

   This creates a local image ``quay.io/cilium/standalone-dns-proxy:latest``.

#. **Set Up kind Cluster with Cilium**

   Create a kind cluster and build/install Cilium from source:

   .. code-block:: shell-session

      $ make kind && make kind-image && make kind-install-cilium

#. **Load the Standalone DNS Proxy Image into kind**

   Load the standalone DNS proxy image you built into the kind cluster:

   .. code-block:: shell-session

      $ kind load docker-image quay.io/cilium/standalone-dns-proxy:latest

#. **Upgrade Cilium to Enable Standalone DNS Proxy**

   Enable the standalone DNS proxy and configure it to work with the Cilium agent:

   .. code-block:: shell-session

      $ cilium upgrade \
          --chart-directory='./install/kubernetes/cilium' \
          --set='l7Proxy=true' \
          --set='dnsProxy.proxyPort=10094' \
          --helm-set='standaloneDnsProxy.enabled=true' \
          --helm-set='standaloneDnsProxy.image.repository=quay.io/cilium/standalone-dns-proxy' \
          --helm-set='standaloneDnsProxy.image.tag=latest' \
          --helm-set='standaloneDnsProxy.image.useDigest=false' \
          --helm-set='standaloneDnsProxy.image.pullPolicy=Never'

   The configuration flags in this example ensure the standalone proxy is operational by applying the following configurations:

   * ``dnsProxy.proxyPort=10094`` sets the DNS proxy port used by both the agent and standalone DNS proxy
   * ``l7Proxy=true`` enables L7 proxy support required for DNS policy enforcement
   * The standalone DNS proxy automatically inherits DNS settings from the agent configuration
   * ``image.tag=latest`` and ``image.pullPolicy=Never`` are used to reference the locally-built image

#. **Restart Cilium Agent**

   Restart the Cilium agent to apply the configuration changes:

   .. code-block:: shell-session

      $ kubectl rollout restart ds -n kube-system cilium

#. **Verify Deployment**

   Check that the standalone DNS proxy pods are running:

   .. code-block:: shell-session

      $ kubectl -n kube-system get pods -l k8s-app=standalone-dns-proxy
      NAME                          READY   STATUS    RESTARTS   AGE
      standalone-dns-proxy-xxxxx    1/1     Running   0          1m

#. **Apply DNS Policy**

   Apply a policy that allows pods with the label ``org: alliance`` to query specific domains
   (``cilium.io`` and its subdomains) and blocks all other queries:

   .. literalinclude:: ../../examples/policies/l7/dns/dns.yaml
      :language: yaml

   .. code-block:: shell-session

      $ kubectl apply -f examples/policies/l7/dns/dns.yaml

#. **Deploy Test Pod**

   Create a test pod with the matching label:

   .. code-block:: shell-session

      $ kubectl run test-pod --image=nicolaka/netshoot --labels="org=alliance" -- sleep 3600

#. **Verify DNS Policy Enforcement**

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

#. **Test Standalone Proxy Resilience**

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

#. **Restore Cilium Agent**

    Restore the Cilium agent to normal operation:

    .. code-block:: shell-session

       $ kubectl rollout undo ds/cilium -n kube-system

For more information on DNS policies, see :ref:`DNS based`.

Limitations
===========

The Standalone DNS Proxy alpha release has the following known limitations:

* The standalone DNS proxy uses the agent's DNS configuration. The ``dnsProxy.proxyPort`` 
  must be explicitly set to a non-zero value when the standalone DNS proxy is enabled 
  (it does not automatically select a free port).
* Metrics related to DNS are not supported yet. The metrics are currently
  only available from the in-agent DNS proxy.
* Standalone DNS proxy depends on Cilium agent to read DNS policies, enforce them and 
  communicate via gRPC. If there are connectivity issues between the proxy and agent,
  DNS policy enforcement may be affected.
* While the standalone DNS proxy can continue to proxy DNS requests when the agent is down,
  it cannot allocate new identities for domains that haven't been observed before.
  If an endpoint looks up a new domain (one that hasn't been cached) while the agent is unavailable,
  the resulting traffic will be dropped because no security identity can be allocated.
  Only DNS lookups for previously observed domains (with cached identities) will work during agent downtime.

Troubleshooting
===============

Validation Errors
-----------------

If the Helm chart fails with a validation error about ``dnsProxy.proxyPort``::

   Error: standaloneDnsProxy requires dnsProxy.proxyPort to be set to a non-zero value (e.g., 10094)

This means you need to explicitly configure the DNS proxy port in your values:

.. code-block:: yaml

   dnsProxy:
     proxyPort: 10094  # Must be non-zero

Port Configuration Verification
-------------------------------

To verify that the DNS proxy port is correctly configured:

.. code-block:: shell-session

   $ kubectl -n kube-system get configmap cilium-config -o yaml | grep 'tofqdns-proxy-port'
   $ kubectl -n kube-system get configmap standalone-dns-proxy-config -o yaml | grep 'tofqdns-proxy-port'

Both ConfigMaps should show the same value from ``dnsProxy.proxyPort``.

gRPC Communication Issues
-------------------------

If there are communication issues between the proxy and agent, review agent logs for connection errors:

.. code-block:: shell-session

   $ kubectl -n kube-system logs -l k8s-app=cilium --tail=100 | grep -i "fqdn.sdp-grpc-server"

API Reference
=============

For detailed API documentation, see :ref:`sdpapi_ref`.

Further Reading
===============

* :ref:`DNS based`
* :ref:`DNS Proxy`
