.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _ip_packet_tracing_tutorial:

***************************************************
Tutorial: Monitoring Generic IP Options with Cilium
***************************************************

This tutorial demonstrates how to configure Cilium to detect, extract, and
monitor arbitrary IP Options from network packets.

Cilium v1.19 and later implements IP Options packet tracing.
IP Options tracing supports reading specific IP Options (configured via Helm) and displaying
the extracted data within Cilium Monitor and Hubble. This capability is
essential for observing network metadata injected by sidecars or upstream
appliances.

Note that Cilium is responsible only for observing this metadata. You are
responsible for ensuring that your applications, sidecars, or network devices
are configured to inject the desired IP Options into the traffic.

Prerequisites
=============

* Dependencies: ``kind``, ``helm``, ``docker``, ``Hubble`` CLI, and the ``cilium`` CLI.

Cluster Setup
=============

Create a kind cluster and install Cilium with the ``bpf.monitorTraceIPOption``
flag enabled.

#. Configure kind

   Create a ``kind-config-ip-tracing.yaml`` file based on the following template. This will
   create 2 nodes (1 control plane and 1 worker).

   .. code-block:: yaml

      kind: Cluster
      apiVersion: kind.x-k8s.io/v1alpha4
      nodes:
      - role: control-plane
      - role: worker
      networking:
        disableDefaultCNI: true

#. Create the kind Cluster

   .. code-block:: shell-session

      kind create cluster --config=kind-config-ip-tracing.yaml

#. Setup Helm Repository

   Add the Cilium Helm repository if you haven't already

   .. code-block:: shell-session

      helm repo add cilium https://helm.cilium.io/

#. Install Cilium with IP Option Monitoring and restart the agent

   Install Cilium using Helm. The key flag here is ``--set bpf.monitorTraceIPOption=136``.
   This flag configures Cilium to extract data from IP Option 136 packets. IP option 136 represents a "Stream ID",
   which will be used later in this guide to generate tracing packets.

    .. cilium-helm-install::
       :namespace: kube-system
       :set: hubble.enabled=true
             hubble.relay.enabled=true
             hubble.ui.enabled=true
             bpf.monitorTraceIPOption=136
       :post-commands: kubectl -n kube-system wait --for=condition=ready pod -l k8s-app=cilium --timeout=300s

Manual Verification
===================

To verify the feature, manually inject a known Trace ID into packets using ``nping``.
The following examples uses a payload of 4 bytes to meet the strict length requirements.

#. Deploy Client and Server Pods
   Deploy an ``nginx`` server and a ``netshoot`` client (containing ``nping``):

   .. literalinclude:: ../../../examples/kubernetes-ip-options/ip-options-pods.yaml
      :language: yaml

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-ip-options/ip-options-pods.yaml

   Wait for the deployments to become ready

   .. code-block:: shell-session

       kubectl rollout status deployment client
       kubectl rollout status deployment server

#. Trigger Traffic with Valid IP Options

   Execute ``nping`` from the client to the server, manually specifying the IP Option hex string.

   .. code-block:: shell-session

       # 1. Get the IP of the server pod
       server_ip=$(kubectl get pods -l app=server -o jsonpath='{.items[0].status.podIP}')

       # 2. Run nping with Option 136 (0x88)
       # Format: \x88 (Type 136) \x04 (Data + header length) \x34\x21 (Data/ID)
       # The data 0x3421 corresponds to decimal 13345.
       # Note: Length must be exactly 2, 4 or 8 bytes of payload. Length 4 for the message indicates 2 bytes of payload
       kubectl exec deployment/client -- nping --tcp -p 80 --ip-options '\x88\x04\x34\x21' -c 3 ${server_ip}

Observing with Hubble
=====================

With traffic flowing, use the Hubble CLI to observe the extracted data.

#. Build and Connect Hubble

   .. code-block:: shell-session

       cd hubble
       make hubble
       cilium hubble port-forward &

#. Filter by Trace ID

   Filter specifically for the injected ID ``13345`` (hex ``0x3421``):

   .. code-block:: shell-session

       ./hubble observe -f --ip-trace-id 13345

   Verify that flows between the ``client`` and ``server`` pods appear with the matching ID.
