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

.. include:: ../tls-cert.rst

Deploy the Gateway and HTTPRoute
================================

The Gateway configuration for this demo provides the similar routing to the
``details`` and ``productpage`` services.


.. tabs::

    .. group-tab:: Self-signed Certificate

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/basic-https.yaml

    .. group-tab:: Cert Manager

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
    NAME          CLASS    ADDRESS         READY   AGE
    tls-gateway   cilium   10.104.247.23   True    29s

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

    .. group-tab:: Cert Manager

        .. code-block:: shell-session

            $ curl https://bookinfo.cilium.rocks/details/1
            $ curl https://hipstershop.cilium.rocks/

