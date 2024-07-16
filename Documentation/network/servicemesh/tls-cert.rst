Create TLS Certificate and Private Key
======================================

.. tabs::

    .. group-tab:: Self-signed Certificate

        For demonstration purposes we will use a TLS certificate signed by a made-up,
        `self-signed <https://cert-manager.io/docs/faq/terminology/#what-does-self-signed-mean-is-my-ca-self-signed>`_
        certificate authority (CA). One easy way to do this is with `minica <https://github.com/jsha/minica>`_.
        We want a certificate that will validate ``bookinfo.cilium.rocks`` and
        ``hipstershop.cilium.rocks``, as these are the host names used in this example.

        .. code-block:: shell-session

            $ minica -domains '*.cilium.rocks'

        On first run, ``minica`` generates a CA certificate and key (``minica.pem`` and
        ``minica-key.pem``). It also creates a directory called ``_.cilium.rocks``
        containing a key and certificate file that we will use for the TLS configuration.

        Create a Kubernetes secret with this demo key and certificate:

        .. code-block:: shell-session

            $ kubectl create secret tls demo-cert --key=_.cilium.rocks/key.pem --cert=_.cilium.rocks/cert.pem

    .. group-tab:: cert-manager

        Let us install cert-manager:

        .. code-block:: shell-session

            $ helm repo add jetstack https://charts.jetstack.io
            $ helm install cert-manager jetstack/cert-manager --version v1.10.0 \
                --namespace cert-manager \
                --set installCRDs=true \
                --create-namespace \
                --set "extraArgs={--enable-gateway-api}"

        Now, create a CA Issuer:

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/ca-issuer.yaml
