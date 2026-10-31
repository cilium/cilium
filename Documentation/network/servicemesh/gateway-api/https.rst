.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_https:

*************
HTTPS Example
*************

This example builds on the previous :ref:`gs_gateway_http` and add TLS
termination for two HTTP routes. For simplicity, the second route to ``productpage``
is omitted.

.. literalinclude:: ../../../../examples/kubernetes/gateway/basic-https.yaml
     :language: yaml

.. include:: ../tls-cert.rst

Deploy the Gateway and HTTPRoute
================================

The Gateway configuration for this demo provides the similar routing to the
``details`` and ``productpage`` services.


.. tabs::

    .. group-tab:: Self-signed Certificate

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/basic-https.yaml

    .. group-tab:: cert-manager

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/basic-https.yaml

        To tell cert-manager that this Ingress needs a certificate, annotate the
        Gateway with the name of the CA issuer we previously created:

        .. code-block:: shell-session

            $ kubectl annotate gateway tls-gateway cert-manager.io/issuer=ca-issuer

        This creates a Certificate object along with a Secret containing the TLS
        certificate.

        .. code-block:: shell-session

            $ kubectl get certificate,secret demo-cert
            NAME                                    READY   SECRET      AGE
            certificate.cert-manager.io/demo-cert   True    demo-cert   29s
            NAME               TYPE                DATA   AGE
            secret/demo-cert   kubernetes.io/tls   3      29s

External IP address will be shown up in Gateway. Also, the host names should be shown up in
related HTTPRoutes.

.. code-block:: shell-session

    $ kubectl get gateway tls-gateway
    NAME          CLASS    ADDRESS         PROGRAMMED   AGE
    tls-gateway   cilium   10.104.247.23   True         29s

    $ kubectl get httproutes https-app-route-1 https-app-route-2
    NAME                HOSTNAMES                      AGE
    https-app-route-1   ["bookinfo.cilium.rocks"]      29s
    https-app-route-2   ["hipstershop.cilium.rocks"]   29s

Update ``/etc/hosts`` with the host names and IP address of the Gateway:

.. code-block:: shell-session

    $ sudo perl -ni -e 'print if !/\.cilium\.rocks$/d' /etc/hosts; sudo tee -a /etc/hosts \
      <<<"$(kubectl get gateway tls-gateway -o jsonpath='{.status.addresses[0].value}') bookinfo.cilium.rocks hipstershop.cilium.rocks"

Make HTTPS Requests
===================

.. tabs::

    .. group-tab:: Self-signed Certificate

        By specifying the CA's certificate on a curl request, you can say that you trust certificates
        signed by that CA.

        .. code-block:: shell-session

            $ curl --cacert minica.pem -v https://bookinfo.cilium.rocks/details/1
            $ curl --cacert minica.pem -v https://hipstershop.cilium.rocks/

        If you prefer, instead of supplying the CA you can specify ``-k`` to tell the
        curl client not to validate the server's certificate. Without either, you
        will get an error that the certificate was signed by an unknown authority.

        Specifying -v on the curl request, you can see that the TLS handshake took
        place successfully.

    .. group-tab:: cert-manager

        .. code-block:: shell-session

            $ curl https://bookinfo.cilium.rocks/details/1
            $ curl https://hipstershop.cilium.rocks/

Share TLS Session Ticket Keys
=============================

By default, each Envoy instance generates its own TLS session ticket keys.
To allow clients to resume TLS sessions when they connect to a different Envoy
instance, configure Gateway API to use a shared Kubernetes Secret.

Create an Opaque Secret containing a key named ``tls.sessionticket.key`` with
exactly 80 bytes of cryptographically secure random data. Up to nine previous
keys can be retained as ``tls.sessionticket.key.1`` through
``tls.sessionticket.key.9``. Use binary files so Kubernetes stores the raw bytes,
rather than a base64 string, in the Secret:

.. code-block:: shell-session

    $ ticket_dir=$(mktemp -d)
    $ chmod 700 "$ticket_dir"
    $ (umask 077; openssl rand 80 > "$ticket_dir/tls.sessionticket.key")
    $ kubectl -n kube-system create secret generic cilium-gateway-session-tickets \
        --from-file=tls.sessionticket.key="$ticket_dir/tls.sessionticket.key"
    $ rm -rf "$ticket_dir"

Set the following Helm values when installing or upgrading Cilium:

.. code-block:: yaml

    gatewayAPI:
      enabled: true
      sessionTicketKeysSecret:
        name: cilium-gateway-session-tickets
        namespace: kube-system

Both values must be configured together. With secret synchronization enabled,
Cilium copies the Secret to ``gatewayAPI.secretsNamespace.name`` and distributes
it to Envoy through SDS. If synchronization is disabled, maintain the Secret copy
in that namespace externally, using the same naming convention as other Gateway
API secrets.

To rotate keys, update the Secret with a new ``tls.sessionticket.key`` and retain
previous keys in the numbered entries so existing tickets can still be decrypted.
Secret updates are propagated through SDS without restarting Envoy.

.. warning::

    A configured session ticket Secret must exist and contain valid keys before
    enabling this feature. Envoy does not fall back to generated keys when a
    configured SDS Secret is unavailable. Leave both Helm values empty to retain
    the default per-instance keys.

