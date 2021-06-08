.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _hubble_configure:

********************
Hubble Configuration
********************

This page provides guidance to configure Hubble in a way that suits your
environment. Instructions to enable Hubble are provided as part of each
Cilium :ref:`gs_install` guide.

.. _hubble_configure_tls_certs:

Use custom TLS certificates
---------------------------

When Hubble Relay is deployed, Hubble listens on a TCP port on the host
network. This allows Hubble Relay to communicate with all Hubble instances in
the cluster. Connections between Hubble server and Hubble Relay instances are
secured using mutual TLS (mTLS) by default.

TLS certificates are automatically generated and distributed as Kubernetes
secrets for use by Hubble and Hubble Relay provided that
``hubble.tls.auto.enabled`` is set to ``true`` (default). This is achieved
either via Helm when using Helm or via a Kubernetes CronJob when using
``experimental-install.yaml``.

.. note::

   When using Helm, TLS certificates are (re-)generated every time Helm is used
   for install or upgrade. As Hubble server and Hubble Relay support TLS
   certificates hot reloading, including CA certificates, this does not disrupt
   any existing connection. New connections are automatically established using
   the new certificates without having to restart Hubble server or Hubble
   Relay.

Hubble allows using custom TLS certificates rather than relying on
automatically generated ones. This can be useful when using Hubble Relay in a
cluster mesh scenario for instance or when using certificates signed by a
specific certificate authority (CA) is required.

In order to use custom TLS certificates ``hubble.tls.auto.enabled`` must
be set to ``false`` and TLS certificates manually provided.

This can be done by specifying the options below to Helm at install or upgrade time::

    --set hubble.tls.auto.enabled=false                          # disable automatic TLS certificate generation
    --set-file hubble.tls.ca.cert=ca.crt.b64                     # certificate of the CA that signs all certificates
    --set-file hubble.tls.server.cert=server.crt.b64             # certificate for Hubble server
    --set-file hubble.tls.server.key=server.key.b64              # private key for the Hubble server certificate
    --set-file hubble.relay.tls.client.cert=relay-client.crt.b64 # client certificate for Hubble Relay to connect to Hubble instances
    --set-file hubble.relay.tls.client.key=relay-client.key.b64  # private key for Hubble Relay client certificate
    --set-file hubble.relay.tls.server.cert=relay-server.crt.b64 # server certificate for Hubble Relay
    --set-file hubble.relay.tls.server.key=relay-server.key.b64  # private key for Hubble Relay server certificate

Options ``hubble.relay.tls.server.cert`` and ``hubble.relay.tls.server.key``
only need to be provided when ``hubble.relay.tls.server.enabled`` is set to
``true`` to enable TLS for the Hubble Relay server (defaults to ``false``).

.. note::

   Provided files must be **base64 encoded** PEM certificates.

   In addition, the **Common Name (CN)** and **Subject Alternative Name (SAN)**
   of the certificate for Hubble server MUST be set to
   ``*.{cluster-name}.hubble-grpc.cilium.io`` where ``{cluster-name}`` is the
   cluster name defined by ``cluster.name`` (defaults to ``default``).
