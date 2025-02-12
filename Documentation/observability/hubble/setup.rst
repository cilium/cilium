.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _hubble_setup:

*******************************
Setting up Hubble Observability
*******************************

Hubble is the observability layer of Cilium and can be used to obtain
cluster-wide visibility into the network and security layer of your Kubernetes
cluster.

.. note::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
   information. If unsure, run ``cilium status`` and validate that Cilium is up
   and running.

Enable Hubble in Cilium
=======================

.. tip::

    Enabling Hubble requires the TCP port 4244 to be open on all nodes running
    Cilium. This is required for Relay to operate correctly.

.. tabs::

    .. group-tab:: Cilium CLI

        In order to enable Hubble and install Hubble relay, run the
        command ``cilium hubble enable`` as shown below:

        .. code-block:: shell-session

            $ cilium hubble enable
            🔑 Found existing CA in secret cilium-ca
            ✨ Patching ConfigMap cilium-config to enable Hubble...
            ♻️  Restarted Cilium pods
            🔑 Generating certificates for Relay...
            2021/04/13 17:11:23 [INFO] generate received request
            2021/04/13 17:11:23 [INFO] received CSR
            2021/04/13 17:11:23 [INFO] generating key: ecdsa-256
            2021/04/13 17:11:23 [INFO] encoded CSR
            2021/04/13 17:11:23 [INFO] signed certificate with serial number 365589302067830033295858933512588007090526050046
            2021/04/13 17:11:24 [INFO] generate received request
            2021/04/13 17:11:24 [INFO] received CSR
            2021/04/13 17:11:24 [INFO] generating key: ecdsa-256
            2021/04/13 17:11:24 [INFO] encoded CSR
            2021/04/13 17:11:24 [INFO] signed certificate with serial number 644167683731852948186644541769558498727586273511
            ✨ Deploying Relay...

    .. group-tab:: Helm

        If you installed Cilium via ``helm install``, Hubble is enabled by default.
        You may enable Hubble Relay with the following command:

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace kube-system \\
              --reuse-values \\
              --set hubble.relay.enabled=true

Run ``cilium status`` to validate that Hubble is enabled and running:

.. code-block:: shell-session

    $ cilium status
        /¯¯\
     /¯¯\__/¯¯\    Cilium:             OK
     \__/¯¯\__/    Operator:           OK
     /¯¯\__/¯¯\    Envoy DaemonSet:    OK
     \__/¯¯\__/    Hubble Relay:       OK
        \__/       ClusterMesh:        disabled

    DaemonSet             cilium                   Desired: 1, Ready: 1/1, Available: 1/1
    DaemonSet             cilium-envoy             Desired: 1, Ready: 1/1, Available: 1/1
    Deployment            cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
    Deployment            hubble-relay             Desired: 1, Ready: 1/1, Available: 1/1
    Containers:           cilium                   Running: 1
                          cilium-envoy             Running: 1
                          cilium-operator          Running: 1
                          clustermesh-apiserver
                          hubble-relay             Running: 1
    Cluster Pods:         8/8 managed by Cilium
    Helm chart version:   1.17.0
    Image versions        cilium             quay.io/cilium/cilium:latest: 1
                          cilium-envoy       quay.io/cilium/cilium-envoy:v1.32.3-1739240299-e85e926b0fa4cec519cefff54b60bd7942d7871b@sha256:ced8a89d642d10d648471afc2d8737238f1479c368955e6f2553ded58029ac88: 1
                          cilium-operator    quay.io/cilium/operator-generic-ci:latest: 1
                          hubble-relay       quay.io/cilium/hubble-relay-ci:latest: 1

.. _hubble_cli_install:

Install the Hubble Client
=========================

In order to access the observability data collected by Hubble, you must first install Hubble CLI.

Select the tab for your platform below and install the latest release of Hubble CLI.

.. tabs::

   .. group-tab:: Linux

      Download the latest hubble release:

      .. code-block:: shell-session

         HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
         HUBBLE_ARCH=amd64
         if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
         curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
         sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
         sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
         rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}

   .. group-tab:: MacOS

      Download the latest hubble release:

      .. code-block:: shell-session

         HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
         HUBBLE_ARCH=amd64
         if [ "$(uname -m)" = "arm64" ]; then HUBBLE_ARCH=arm64; fi
         curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-darwin-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
         shasum -a 256 -c hubble-darwin-${HUBBLE_ARCH}.tar.gz.sha256sum
         sudo tar xzvfC hubble-darwin-${HUBBLE_ARCH}.tar.gz /usr/local/bin
         rm hubble-darwin-${HUBBLE_ARCH}.tar.gz{,.sha256sum}

   .. group-tab:: Windows

      Download the latest hubble release:

      .. code-block:: shell-session

         curl -LO "https://raw.githubusercontent.com/cilium/hubble/master/stable.txt"
         set /p HUBBLE_VERSION=<stable.txt
         curl -L --fail -O "https://github.com/cilium/hubble/releases/download/%HUBBLE_VERSION%/hubble-windows-amd64.tar.gz"
         curl -L --fail -O "https://github.com/cilium/hubble/releases/download/%HUBBLE_VERSION%/hubble-windows-amd64.tar.gz.sha256sum"
         certutil -hashfile hubble-windows-amd64.tar.gz SHA256
         type hubble-windows-amd64.tar.gz.sha256sum
         :: verify that the checksum from the two commands above match
         tar zxf hubble-windows-amd64.tar.gz

      and move the ``hubble.exe`` CLI to a directory listed in the ``%PATH%`` environment variable after
      extracting it from the tarball.

.. _hubble_validate_api_access:

Validate Hubble API Access
==========================

.. include:: port-forward.rst

Now you can validate that you can access the Hubble API via the installed CLI:

.. code-block:: shell-session

    $ hubble status -P
    Healthcheck (via 127.0.0.1:4245): Ok
    Current/Max Flows: 11917/12288 (96.98%)
    Flows/s: 11.74
    Connected Nodes: 3/3

You can also query the flow API and look for flows:

.. code-block:: shell-session

   $ hubble observe -P
   Feb 12 19:13:58.111: kube-system/hubble-relay-6467f4f4d-xrxfs:47550 (ID:95552) -> 172.18.0.2:4244 (host) to-stack FORWARDED (TCP Flags: ACK, PSH)
   ...

.. note::

   If you port forward to a port other than ``4245`` (``--port-forward-port PORT``
   when using automatic port-forwarding), make sure to use the ``--server`` flag
   or ``HUBBLE_SERVER`` environment variable to set the Hubble server address
   (default: ``localhost:4245``).

   For more information, check out Hubble CLI's help message by running ``hubble help status``
   or ``hubble help observe`` as well as ``hubble config`` for  configuring Hubble CLI.

.. note::

   If you have :ref:`enabled TLS<hubble_enable_tls>` then you will need to specify additional flags to :ref:`access the Hubble API<hubble_api_tls>`.

Troubleshooting Hubble Deployment
=================================

Validate the state of Hubble and/or Hubble Relay by running ``cilium status``:

.. code-block:: shell-session

    $ cilium status
        /¯¯\
     /¯¯\__/¯¯\    Cilium:             OK
     \__/¯¯\__/    Operator:           OK
     /¯¯\__/¯¯\    Envoy DaemonSet:    OK
     \__/¯¯\__/    Hubble Relay:       OK
        \__/       ClusterMesh:        disabled

    DaemonSet             cilium                   Desired: 1, Ready: 1/1, Available: 1/1
    DaemonSet             cilium-envoy             Desired: 1, Ready: 1/1, Available: 1/1
    Deployment            cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
    Deployment            hubble-relay             Desired: 1, Ready: 1/1, Available: 1/1
    Containers:           cilium                   Running: 1
                          cilium-envoy             Running: 1
                          cilium-operator          Running: 1
                          clustermesh-apiserver
                          hubble-relay             Running: 1
    Cluster Pods:         8/8 managed by Cilium
    Helm chart version:   1.17.0
    Image versions        cilium             quay.io/cilium/cilium:latest: 1
                          cilium-envoy       quay.io/cilium/cilium-envoy:v1.32.3-1739240299-e85e926b0fa4cec519cefff54b60bd7942d7871b@sha256:ced8a89d642d10d648471afc2d8737238f1479c368955e6f2553ded58029ac88: 1
                          cilium-operator    quay.io/cilium/operator-generic-ci:latest: 1
                          hubble-relay       quay.io/cilium/hubble-relay-ci:latest: 1

Hubble Relay
------------

If Hubble Relay is enabled, ``cilium status`` should display: ``OK``.
Otherwise, we should expect to see errors/warnings reported:

.. code-block:: shell-session

    $ cilium status
        /¯¯\
     /¯¯\__/¯¯\    Cilium:             OK
     \__/¯¯\__/    Operator:           OK
     /¯¯\__/¯¯\    Envoy DaemonSet:    OK
     \__/¯¯\__/    Hubble Relay:       1 errors, 2 warnings
        \__/       ClusterMesh:        disabled

    DaemonSet              cilium                   Desired: 1, Ready: 1/1, Available: 1/1
    DaemonSet              cilium-envoy             Desired: 1, Ready: 1/1, Available: 1/1
    Deployment             cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
    Deployment             hubble-relay             Desired: 1, Unavailable: 1/1
    Containers:            cilium                   Running: 1
                           cilium-envoy             Running: 1
                           cilium-operator          Running: 1
                           clustermesh-apiserver
                           hubble-relay             Pending: 1
    Cluster Pods:          8/8 managed by Cilium
    Helm chart version:    1.17.0
    Image versions         cilium             quay.io/cilium/cilium:latest: 1
                           cilium-envoy       quay.io/cilium/cilium-envoy:v1.32.3-1739240299-e85e926b0fa4cec519cefff54b60bd7942d7871b@sha256:ced8a89d642d10d648471afc2d8737238f1479c368955e6f2553ded58029ac88: 1
                           cilium-operator    quay.io/cilium/operator-generic-ci:latest: 1
                           hubble-relay       quay.io/cilium/hubble-relay-ci:latest-: 1
    Errors:                hubble-relay       hubble-relay                     1 pods of Deployment hubble-relay are not ready
    Warnings:              hubble-relay       hubble-relay-85f98cc7df-s2lkq    pod is pending
                           hubble-relay       hubble-relay-85f98cc7df-s2lkq    pod is pending

.. tip::

    If warnings or errors are reported for both ``Cilium`` and ``Hubble Relay``, it
    often hints at a misconfiguration in Hubble or the Hubble system failing to start.
    Since Hubble is a non-critical system running in the Cilium Agent, it is expected
    for the Cilium pods to remain running and healthy even when Hubble fails to start.
    See the :ref:`hubble_setup_troubleshooting` section below for Hubble-specific troubleshooting
    steps.

Verify the state of the pods with:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=hubble-relay
    NAME                           READY   STATUS             RESTARTS      AGE
    hubble-relay-6467f4f4d-x825b   0/1     CrashLoopBackOff   5 (19s ago)   7m28s

If one or more pods are in ``Pending`` state, describe the pod(s) with:

.. code-block:: shell-session

    $ kubectl describe -n kube-system pod/cilium-5bjkq
    Name:             hubble-relay-6467f4f4d-x825b
    Namespace:        kube-system
    ...

If one or more pods are not in ``Running`` state, look at the pod(s) logs with:

.. code-block:: shell-session

    $ kubectl -n kube-system logs hubble-relay-6467f4f4d-x825b
    time="2025-02-12T21:21:40.246596435Z" level=info msg="Starting gRPC health server..." addr=":4222" subsys=hubble-relay
    time="2025-02-12T21:21:40.246611018Z" level=info msg="Starting gRPC server..." options="{peerTarget:hubble-peer.kube-system.svc.cluster.local.:443 retryTimeout:30000000000 listenAddress::4245 healthListenAddress::4222 metricsListenAddress: log:0x400038fc00 serverTLSConfig:<nil> insecureServer:true clientTLSConfig:0x4000b12528 clusterName:cluster insecureClient:false observerOptions:[0x28cb1e0 0x28cb2e0] grpcMetrics:<nil> grpcUnaryInterceptors:[] grpcStreamInterceptors:[]}" subsys=hubble-relay
    time="2025-02-12T21:21:40.251658493Z" level=info msg="Failed to create peer notify client for peers change notification; will try again after the timeout has expired" connection timeout=30s error="rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial tcp 10.96.49.4:443: connect: connection refused\"" subsys=hubble-relay
    time="2025-02-12T21:22:10.25956541Z" level=info msg="Failed to create peer notify client for peers change notification; will try again after the timeout has expired" connection timeout=30s error="rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial tcp 10.96.49.4:443: connect: connection refused\"" subsys=hubble-relay
    time="2025-02-12T21:22:40.265123839Z" level=info msg="Failed to create peer notify client for peers change notification; will try again after the timeout has expired" connection timeout=30s error="rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial tcp 10.96.49.4:443: connect: connection refused\"" subsys=hubble-relay
    time="2025-02-12T21:22:49.055746359Z" level=info msg="Stopping server..." subsys=hubble-relay
    time="2025-02-12T21:22:49.056293486Z" level=info msg="Server stopped" subsys=hubble-relay

If you face a ``connection refused`` error, it means that Hubble-Relay can't connect
to the Hubble API exposed by Cilium agents through the ``hubble-peer`` service.
See the :ref:`hubble_setup_troubleshooting` section below for Hubble-specific troubleshooting
steps.

For TLS related errors, see :ref:`Hubble TLS Troubleshooting<hubble_enable_tls_troubleshooting>`.

.. _hubble_setup_troubleshooting:

Hubble
------

If Hubble is enabled, ``cilium status`` should display: ``OK`` for ``Cilium``.
Otherwise, we should expect to see errors/warnings reported:

.. code-block:: shell-session

    $ cilium status
        /¯¯\
     /¯¯\__/¯¯\    Cilium:             1 warnings
     \__/¯¯\__/    Operator:           OK
     /¯¯\__/¯¯\    Envoy DaemonSet:    OK
     \__/¯¯\__/    Hubble Relay:       1 errors
        \__/       ClusterMesh:        disabled

    DaemonSet              cilium                   Desired: 1, Ready: 1/1, Available: 1/1
    DaemonSet              cilium-envoy             Desired: 1, Ready: 1/1, Available: 1/1
    Deployment             cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
    Deployment             hubble-relay             Desired: 1, Unavailable: 1/1
    Containers:            cilium                   Running: 1
                           cilium-envoy             Running: 1
                           cilium-operator          Running: 1
                           clustermesh-apiserver
                           hubble-relay             Running: 1
    Cluster Pods:          8/8 managed by Cilium
    Helm chart version:    1.17.0
    Image versions         cilium             quay.io/cilium/cilium:latest: 1
                           cilium-envoy       quay.io/cilium/cilium-envoy:v1.32.3-1739240299-e85e926b0fa4cec519cefff54b60bd7942d7871b@sha256:ced8a89d642d10d648471afc2d8737238f1479c368955e6f2553ded58029ac88: 1
                           cilium-operator    quay.io/cilium/operator-generic-ci:latest: 1
                           hubble-relay       quay.io/cilium/hubble-relay-ci:latest: 1
    Errors:                hubble-relay       hubble-relay    1 pods of Deployment hubble-relay are not ready
    Warnings:              cilium             cilium-5bjkq    Hubble: failed to setup metrics: metric 'unknown-metric' does not exist

Verify the state of the pods with:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME           READY   STATUS    RESTARTS      AGE
    cilium-5bjkq   1/1     Running   1 (18m ago)   33m

If one or more pods are in ``Pending`` state, describe the pod(s) with:

.. code-block:: shell-session

    $ kubectl describe -n kube-system pod/cilium-5bjkq
    Name:                 cilium-5bjkq
    Namespace:            kube-system
    ...

If one or more pods are not in ``Running`` state, look at the pod(s) logs with:

.. code-block:: shell-session

    $ kubectl logs -n kube-system -c cilium-agent -l k8s-app=cilium --tail=-1 | grep subsys=hubble
    time="2025-02-12T22:12:01.227357082Z" level=info msg="Starting Hubble Metrics server" address=":9965" metrics=unknown-metric subsys=hubble tls=false
    time="2025-02-12T22:12:01.22740229Z" level=error msg="Failed to launch hubble" error="failed to setup metrics: metric 'unknown-metric' does not exist" subsys=hubble

Next Steps
==========

* :ref:`hubble_cli`
* :ref:`hubble_ui`
* :ref:`hubble_enable_tls`
