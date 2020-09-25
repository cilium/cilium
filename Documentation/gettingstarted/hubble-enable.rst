Enable Hubble
==============

Hubble is a fully distributed networking and security observability platform
for cloud native workloads. It is built on top of Cilium and eBPF to enable
deep visibility into the communication and behavior of services as well as the
networking infrastructure in a completely transparent manner.

* Hubble can be configured to be in **distributed mode** or **local mode**.

  .. tabs::

     .. group-tab:: Distributed Mode


        In **distributed mode**, Hubble listens on a TCP port on the host network.
        This allows :ref:`hubble_relay` to communicate with all the Hubble instances in
        the cluster. Hubble CLI and Hubble UI in turn connect to Hubble Relay to provide
        cluster-wide networking visibility.

        .. note::

           In Distributed mode, Hubble runs a gRPC service over HTTP on the
           host network. It is secured using mutual TLS (mTLS) by default to
           only allow access to Hubble Relay. Refer to
           `Use custom TLS certificates in distributed mode (optional)`_ to
           manually provide TLS certificates.

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set global.hubble.enabled=true \\
              --set global.hubble.listenAddress=":4244" \\
              --set global.hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \\
              --set global.hubble.relay.enabled=true \\
              --set global.hubble.ui.enabled=true

     .. group-tab:: Local Mode

        In **local mode**, Hubble listens on a UNIX domain socket. You can connect to a
        Hubble instance by running ``hubble`` command from inside the Cilium pod. This
        provides networking visibility for traffic observed by the local Cilium agent.

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set global.hubble.enabled=true \\
              --set global.hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"

* Restart the Cilium daemonset to allow Cilium agent to pick up the ConfigMap changes:

  .. parsed-literal::

      kubectl rollout restart -n $CILIUM_NAMESPACE ds/cilium

* To pick one Cilium instance and validate that Hubble is properly configured to listen on
  a UNIX domain socket:

  .. parsed-literal::

      kubectl exec -n $CILIUM_NAMESPACE -t ds/cilium -- hubble observe

* **(Distributed mode only)** To validate that Hubble Relay is running, install the ``hubble``
  CLI:

  .. include:: hubble-install.rst

  Once the ``hubble`` CLI is installed, set up a port forwarding for ``hubble-relay`` service and
  run ``hubble observe`` command:

  .. parsed-literal::

      kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-relay --address 0.0.0.0 --address :: 4245:80
      hubble observe --server localhost:4245

  (**For Linux / MacOS**) For convenience, you may set and export the ``HUBBLE_DEFAULT_SOCKET_PATH``
  environment variable:

  .. code:: bash

    $ export HUBBLE_DEFAULT_SOCKET_PATH=localhost:4245

  This will allow you to use ``hubble status`` and ``hubble observe`` commands
  without having to specify the server address via the ``--server`` flag.

* **(Distributed mode only)** To validate that Hubble UI is properly configured, set up a port forwarding for
  ``hubble-ui`` service:

  .. parsed-literal::

      kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-ui --address 0.0.0.0 --address :: 12000:80

  and then open http://localhost:12000/.

Use custom TLS certificates in distributed mode (optional)
----------------------------------------------------------

In **distributed mode**, Hubble listens on a TCP port on the host network. This
allows :ref:`hubble_relay` to communicate with all Hubble instances in the
cluster. Connections between Hubble server and Hubble Relay instances are
secured using mutual TLS (mTLS) by default.

When using Helm, TLS certificates are automatically generated and distributed
as Kubernetes secrets by Helm for use by Hubble and Hubble Relay provided that
``global.hubble.tls.auto.enabled`` is set to ``true`` (default).

.. note::

   TLS certificates are (re-)generated every time Helm is used for install or
   upgrade. As Hubble server and Hubble Relay support TLS certificates hot
   reloading, including CA certificates, this does not disrupt any existing
   connection. New connections are automatically established using the new
   certificates without having to restart Hubble server or Hubble Relay.

Hubble allows using custom TLS certificates rather than relying on
automatically generated ones. This can be useful when using Hubble in
distributed mode in a cluster mesh scenario for instance or when using
certificates signed by a specific certificate authority (CA) is required.

In order to use custom TLS certificates ``global.hubble.tls.auto.enabled`` must
be set to ``false`` and TLS certificates manually provided.

This can be done by specifying the options below to Helm at install or upgrade time:

.. parsed-literal::
    --set global.hubble.tls.auto.enabled=false                  # disable automatic TLS certificate generation
    --set-file hubble-tls.ca.crt=ca.crt.b64                     # certificate of the CA that signs all certificates
    --set-file hubble-tls.server.crt=server.crt.b64             # certificate for Hubble server
    --set-file hubble-tls.server.key=server.key.b64             # private key for the Hubble server certificate
    --set-file hubble-tls.relay.client.crt=relay-client.crt.b64 # client certificate for Hubble Relay to connect to Hubble instances
    --set-file hubble-tls.relay.client.key=relay-client.key.b64 # private key for Hubble Relay client certificate
    --set-file hubble-tls.relay.server.crt=relay-server.crt.b64 # server certificate for Hubble Relay
    --set-file hubble-tls.relay.server.key=relay-server.key.b64 # private key for Hubble Relay server certificate

Options ``hubble-tls.relay.server.crt`` and ``hubble-tls.relay.server.key``
only need to be provided when ``global.hubble.relay.tls.enabled`` is set to
``true`` to enable TLS for the Hubble Relay server (defaults to ``false``).

.. note::

   Provided files must be **base64 encoded** PEM certificates.

   In addition, the **Common Name (CN)** and **Subject Alternative Name (SAN)**
   of the certificate for Hubble server MUST be set to
   ``*.{cluster-name}.hubble-grpc.cilium.io`` where ``{cluster-name}`` is the
   cluster name defined by ``global.cluster.name`` (defaults to ``default``).
