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

TLS certificates
================

When Hubble Relay is deployed, Hubble listens on a TCP port on the host
network. This allows Hubble Relay to communicate with all Hubble instances in
the cluster. Connections between Hubble server and Hubble Relay instances are
secured using mutual TLS (mTLS) by default.

TLS certificates can be provided by manually on the Helm install command (user
provided) or generate automatically via either:

* `helm <https://helm.sh/docs/chart_template_guide/function_list/#gensignedcert>`__
* cilium's `certgen <https://github.com/cilium/certgen>`__ (using a Kubernetes CronJob)
* `cert-manager <https://cert-manager.io/>`__

User provided certificates
--------------------------

In order to use custom TLS certificates ``hubble.tls.auto.enabled`` must
be set to ``false`` and TLS certificates manually provided.
This can be done by specifying the options below to Helm at install or upgrade time.

::

    --set hubble.tls.auto.enabled=false                          # disable automatic TLS certificate generation
    --set-file hubble.tls.ca.cert=ca.crt.b64                     # certificate of the CA that signs all certificates
    --set-file hubble.tls.server.cert=server.crt.b64             # certificate for Hubble server
    --set-file hubble.tls.server.key=server.key.b64              # private key for the Hubble server certificate
    --set-file hubble.relay.tls.client.cert=relay-client.crt.b64 # client certificate for Hubble Relay to connect to Hubble instances
    --set-file hubble.relay.tls.client.key=relay-client.key.b64  # private key for Hubble Relay client certificate
    --set-file hubble.relay.tls.server.cert=relay-server.crt.b64 # server certificate for Hubble Relay
    --set-file hubble.relay.tls.server.key=relay-server.key.b64  # private key for Hubble Relay server certificate
    --set-file hubble.ui.tls.client.cert=ui-client.crt.b64       # client certificate for Hubble UI
    --set-file hubble.ui.tls.client.key=ui-client.key.b64        # private key for Hubble UI client certificate

Options ``hubble.relay.tls.server.cert``, ``hubble.relay.tls.server.key``
``hubble.ui.tls.client.cert`` and ``hubble.ui.tls.client.key``
only need to be provided when ``hubble.relay.tls.server.enabled=true`` (default ``false``)
which enable TLS for the Hubble Relay server.

.. note::

   Provided files must be **base64 encoded** PEM certificates.

   In addition, the **Common Name (CN)** and **Subject Alternative Name (SAN)**
   of the certificate for Hubble server MUST be set to
   ``*.{cluster-name}.hubble-grpc.cilium.io`` where ``{cluster-name}`` is the
   cluster name defined by ``cluster.name`` (defaults to ``default``).

Auto generated certificates via Helm
------------------------------------

When using Helm, TLS certificates are (re-)generated every time Helm is used
for install or upgrade. As Hubble server and Hubble Relay support TLS
certificates hot reloading, including CA certificates, this does not disrupt
any existing connection. New connections are automatically established using
the new certificates without having to restart Hubble server or Hubble
Relay.

::

    --set hubble.tls.auto.enabled=true               # enable automatic TLS certificate generation
    --set hubble.tls.auto.method=helm                # auto generate certificates using helm method
    --set hubble.tls.auto.certValidityDuration=1095  # certificates validity duration in days (default 3 years)

The downside of this method is certificates are not auto-renewed.
So re-install is required when certificates are expired.

Auto generated certificates via Kubernetes CronJob
--------------------------------------------------

Like helm method, TLS certificates are generated at installation time. And a kubernetes CronJob
is used to schedule for certificates regeneration (regardless of their expiration date).

::

    --set hubble.tls.auto.enabled=true               # enable automatic TLS certificate generation
    --set hubble.tls.auto.method=cronJob             # auto generate certificates using cronJob method
    --set hubble.tls.auto.certValidityDuration=1095  # certificates validity duration in days (default 3 years)
    --set hubble.tls.auto.schedule="0 0 1 */4 *"     # schedule for certificates re-generation (crontab syntax)

Auto generated certificates via cert-manager
--------------------------------------------

This method rely on `cert-manager <https://cert-manager.io/>`__ to generate certificate.
``cert-manager`` now becomes de-facto way to manage TLS on k8s, and compared to above methods,
it has the following advantages:

* No need for extra cronJob
* Support multiple issuers: CA, Vault, Let's Encrypt, Google CAS,...
  You can choose the issuer that fits your organization's requirements.
* Manage certs via a CRD, which is more straightforward than inspecting the PEM file.
* Auto-renew certificates

**Installation steps**:

1. First install `cert-manager <https://cert-manager.io/docs/installation/>`__ and setup `issuer <https://cert-manager.io/docs/configuration/>`_.
   Please make sure that your issuer is be able to create certificates under the ``cilium.io`` domain name.
2. Install/upgrade cilium with bellow configs:

::

    --set hubble.tls.auto.enabled=true               # enable automatic TLS certificate generation
    --set hubble.tls.auto.method=certmanager         # auto generate certificates using cert-manager
    --set hubble.tls.auto.certValidityDuration=1095  # certificates validity duration in days (default 3 years)
    --set hubble.tls.auto.certManagerIssuerRef.group="cert-manager.io" # Reference to cert-manager's issuer
    --set hubble.tls.auto.certManagerIssuerRef.kind="ClusterIssuer"
    --set hubble.tls.auto.certManagerIssuerRef.name="ca-issuer"

**Troubleshooting**:

If you get the following error while install cilium (and cert-manager), it's because
cert-manager ValidatingWebhook (which used to verify the Certificate CRD resources)
is not available (blocked due to CNI is not available).

::

    Error: Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp x.x.x.x:443: connect: connection refused

There are several ways to overcome above issue, such as:

* Option 1: disable validation on cilium installed namespace

.. code-block:: shell-session

    $ # We assume cilium installed in kube-system namespace
    $ kubectl label namespace kube-system cert-manager.io/disable-validation=true

    $ helm install cert-manager ...
    $ kubectl apply -f issuer.yaml
    $ helm install cilium ...

* Option 2: install cert-manager CRDs first

.. code-block:: shell-session

    $ # see https://cert-manager.io/docs/installation/helm/#option-1-installing-crds-with-kubectl
    $ kubectl create -f cert-manager.crds.yaml

    $ # cert-manager MUST be installed after cilium
    $ helm install cilium ...

    $ helm install cert-manager ...
    $ kubectl apply -f issuer.yaml

* Option 3: install cert-manager webhook with hostNetwork

.. code-block:: shell-session

    $ helm install cert-manager jetstack/cert-manager \
            --set webhook.hostNetwork=true \
            --set webhook.tolerations='["operator": "Exists"]'
    $ kubectl apply -f issuer.yaml

    $ helm install cilium ...

* Option 4: upgrade cilium from disabled-TLS installation

.. code-block:: shell-session

    $ helm install cilium cilium/cilium \
            --set hubble.tls.enabled=false \
            ...

    $ helm install cert-manager ...
    $ kubectl apply -f issuer.yaml

    $ # waiting for node ready, and cert-manager available
    $ helm upgrade cilium cilium/cilium \
            --set hubble.tls.enabled=true \
            ...

.. note::

   ``issuer.yaml`` in snippet above is issuer used by cilium.
   See `cert-manager Issuer Configuration docs <https://cert-manager.io/docs/configuration/>`__
   to create that file.
