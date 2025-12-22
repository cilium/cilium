.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_ztunnel:

*************************************
Ztunnel Transparent Encryption (Beta)
*************************************

.. include:: ../../beta.rst

This guide explains how to configure Cilium to use ztunnel for transparent
encryption and mutual TLS (mTLS) authentication between Cilium-managed endpoints.
ztunnel is a purpose-built per-node proxy that provides transparent Layer 4 mTLS
encryption and authentication for pod-to-pod communication.

When ztunnel is enabled in Cilium, the agent running on each cluster node
establishes a control plane connection with the local ztunnel proxy. Cilium
enrolls pods into the mesh on a per-namespace basis, allowing fine-grained
control over which workloads participate in mTLS encryption. Enrolled pods have
their traffic transparently redirected to the ztunnel proxy using iptables rules
configured in their network namespace, where the traffic is encrypted and
authenticated using mutual TLS before being sent to the destination.


Generating secrets for authentication
=====================================

Cilium's ztunnel integration requires a set a set of private keys and
accompanying to certificates be present via Kubernetes secrets. This follows the
same pattern as IPsec key injections.

These keys can be generated with the follow bash script prior to deploying
Cilium.

.. code-block:: bash

   #!/bin/bash

   # == Bootstrap ===
   openssl genrsa -out bootstrap-private.key 2048

   echo '
   [ req ]
   distinguished_name = req_distinguished_name
   x509_extensions = v3_ca
   prompt = no

   [ req_distinguished_name ]
   O = cluster.local

   [ v3_ca ]
   subjectKeyIdentifier = hash
   authorityKeyIdentifier = keyid:always,issuer
   basicConstraints = CA:FALSE
   keyUsage = digitalSignature, keyEncipherment
   extendedKeyUsage = serverAuth, clientAuth
   subjectAltName = @alt_names

   [alt_names]
   DNS.1 = localhost
   ' > openssl.conf

   openssl req -x509 -new -nodes -key bootstrap-private.key -sha256 -days 3650 -out bootstrap-root.crt -config openssl.conf

   # == CA ==
   openssl genrsa -out ca-private.key 2048

   echo '
   [ req ]
   distinguished_name = req_distinguished_name
   x509_extensions = v3_ca
   prompt = no

   [ req_distinguished_name ]
   O = cluster.local

   [ v3_ca ]
   subjectKeyIdentifier = hash
   authorityKeyIdentifier = keyid:always,issuer
   basicConstraints = critical, CA:true
   keyUsage = critical, digitalSignature, cRLSign, keyCertSign
   ' > openssl.conf

   openssl req -x509 -new -nodes -key ca-private.key -sha256 -days 3650 -out ca-root.crt -config openssl.conf

   kubectl --namespace kube-system create secret generic cilium-ztunnel-secrets \
         --from-file=bootstrap-private.key=bootstrap-private.key \
         --from-file=bootstrap-root.crt=bootstrap-root.crt \
         --from-file=ca-private.key=ca-private.key \
         --from-file=ca-root.crt=ca-root.crt

The 'bootstrap' keys are used to secure the connection between ztunnel and
Cilium's xDS and certificate server implementation.

The 'ca' keys are used as the root certificate for creating in-memory and
ephemeral client certificates on ztunnel's request.

The certificate configuration values are pulled directly from a stock
ambient mesh deployment to ensure compatibility. Changing these values may result
in a broken ztunnel integration.

Enable ztunnel in Cilium
========================

Before you install Cilium with ztunnel enabled, ensure that:

1. The necessary Kubernetes secrets are available.
2. Cluster Mesh is not enabled (ztunnel is currently not compatible with Cluster Mesh).

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. parsed-literal::

          cilium install |CHART_VERSION| \
             --set encryption.enabled=true \
             --set encryption.type=ztunnel

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.type=ztunnel

ztunnel may also be enabled manually by setting the ``enable-ztunnel: true``
option in the Cilium ``ConfigMap`` and restarting each Cilium agent instance.

.. note::

   By default, ztunnel listens on the Unix socket at ``/var/run/cilium/ztunnel.sock``.
   If your ztunnel installation uses a different socket path, you can configure it
   using the ``--set ztunnel.zdsUnixAddr=/path/to/ztunnel.sock`` Helm option.

Enrolling Namespaces
====================

After enabling ztunnel in Cilium, you need to explicitly enroll namespaces to
enable mTLS encryption for their workloads. This is done by applying a label
to the namespace:

.. code-block:: shell-session

    kubectl label namespace <namespace-name> mtls-enabled=true

To verify that a namespace is enrolled:

.. code-block:: shell-session

    kubectl get namespace <namespace-name> --show-labels

When a namespace is enrolled:

1. All existing pods in the namespace (except ztunnel pods themselves) are enrolled
2. Iptables rules are configured in each pod's network namespace for traffic redirection
3. Pod metadata is sent to the ztunnel proxy via the ZDS protocol
4. Future pods created in the namespace are automatically enrolled

To disenroll a namespace:

.. code-block:: shell-session

    kubectl label namespace <namespace-name> mtls-enabled-

This will:

1. Disenroll all pods in the namespace from ztunnel
2. Remove the iptables rules from each pod's network namespace
3. Notify ztunnel to stop processing traffic for those workloads

Validate the Setup
==================

1. Check that ztunnel has been enabled:

   .. code-block:: shell-session

      kubectl -n kube-system describe cm cilium-config | grep enable-ztunnel -A2

   You should see output indicating that ztunnel encryption is enabled.

2. Check which namespaces are enrolled:

   .. code-block:: shell-session

      kubectl get namespaces -l mtls-enabled=true

   This shows all namespaces labeled for ztunnel enrollment.

   To verify that these namespaces are actually enrolled in the StateDB table:

   .. code-block:: shell-session

      kubectl exec -n kube-system ds/cilium -- cilium-dbg statedb dump

   Look for the mtls-enrolled-namespaces table to see which namespaces have been
   successfully processed by the enrollment reconciler.

3. Run a ``bash`` shell in one of the Cilium pods hosting a mtls-enrolled pod with
   ``kubectl -n kube-system exec -ti pod/<cillium-pod-hosting-mtls-pod> -- bash`` 
   and execute the following commands:

   Install tcpdump

   .. code-block:: shell-session

       $ apt-get update
       $ apt-get -y install tcpdump

   Check that traffic is encrypted. In the example below, this can be verified
   by the fact that packets will have a destination port of 15008 (HBONE).
   In the example below, ``eth0`` is the interface used for pod-to-pod
   communication. Replace this interface with e.g. ``cilium_vxlan`` if
   tunneling is enabled.

   .. code-block:: shell-session

       tcpdump -i eth0 port 15008
       tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
       listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
       13:00:06.982499 IP 10.244.1.95.15008 > 10.244.2.3.33446: ...
       13:00:06.982536 IP 10.244.2.3.33446 > 10.244.1.95.15008: ...
       13:00:06.982675 IP 10.244.2.3.33446 > 10.244.1.95.15008: ...

      


Limitations
===========

* The ztunnel integration currently only supports enrollment via namespace
  labels. Pod-level enrollment is not supported.

* Only TCP traffic is currently supported for mTLS encryption. UDP and other
  protocols are not redirected to ztunnel.

* The integration requires iptables support in the kernel and cannot be used
  with environments that do not support iptables (such as some minimal container
  runtimes).

Known Issues
============

* Cluster Mesh is not currently supported when ztunnel is enabled. Attempting
  to enable both will result in a validation error.

* Pods without a network namespace path (such as host-networked pods) cannot
  be enrolled in ztunnel and will be skipped during enrollment.

