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

.. tabs::

    .. group-tab:: Cilium CLI

        In order to enable Hubble, run the command ``cilium hubble enable`` as shown
        below:

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


        .. tip::

           Enabling Hubble requires the TCP port 4244 to be open on all nodes running
           Cilium. This is required for Relay to operate correctly.

        Run ``cilium status`` to validate that Hubble is enabled and running:

        .. code-block:: shell-session

            $ cilium status
                /¯¯\
             /¯¯\__/¯¯\    Cilium:         OK
             \__/¯¯\__/    Operator:       OK
             /¯¯\__/¯¯\    Hubble:         OK
             \__/¯¯\__/    ClusterMesh:    disabled
                \__/

            DaemonSet         cilium                   Desired: 3, Ready: 3/3, Available: 3/3
            Deployment        cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
            Deployment        hubble-relay             Desired: 1, Ready: 1/1, Available: 1/1
            Containers:       cilium                   Running: 3
                              cilium-operator          Running: 1
                              hubble-relay             Running: 1
            Image versions    cilium-operator          quay.io/cilium/operator-generic:v1.9.5: 1
                              hubble-relay             quay.io/cilium/hubble-relay:v1.9.5: 1
                              cilium                   quay.io/cilium/cilium:v1.9.5: 3

    .. group-tab:: Helm

        If you installed Cilium via ``helm install``, you may enable Hubble
        Relay and UI with the following command:

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace kube-system \\
              --reuse-values \\
              --set hubble.relay.enabled=true \\
              --set hubble.ui.enabled=true

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
====================================

In order to access the Hubble API, create a port forward to the Hubble service
from your local machine. This will allow you to connect the Hubble client to
the local port ``4245`` and access the Hubble Relay service in your Kubernetes
cluster. For more information on this method, see `Use Port Forwarding to Access Application in a Cluster <https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/>`_.

.. code-block:: shell-session

    $ cilium hubble port-forward&
    Forwarding from 0.0.0.0:4245 -> 4245
    Forwarding from [::]:4245 -> 4245

Now you can validate that you can access the Hubble API via the installed CLI:

.. code-block:: shell-session

    $ hubble status
    Healthcheck (via localhost:4245): Ok
    Current/Max Flows: 11917/12288 (96.98%)
    Flows/s: 11.74
    Connected Nodes: 3/3

You can also query the flow API and look for flows:

.. code-block:: shell-session

   $ hubble observe

.. note::

   If you port forward to a port other than ``4245``, make sure to use the
   ``--server`` flag or ``HUBBLE_SERVER`` environment variable to set the
   Hubble server address (default: ``localhost:4245``). For more information,
   check out Hubble CLI's help message by running ``hubble help status`` or
   ``hubble help observe`` as well as ``hubble config`` for  configuring Hubble
   CLI.

.. note::

   If you have :ref:`enabled TLS<hubble_enable_tls>` then you will need to specify additional flags to :ref:`access the Hubble API<hubble_api_tls>`.

Next Steps
==========

* :ref:`hubble_cli`
* :ref:`hubble_ui`
* :ref:`hubble_enable_tls`
