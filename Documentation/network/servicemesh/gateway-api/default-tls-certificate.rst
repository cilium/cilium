.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_default_tls_certificate:

************************
Default TLS Certificate
************************

A default TLS certificate acts as a fallback when no other certificates match the hostname specified in the SNI header, or when SNI is absent.
The Gateway API specification does not natively support a default TLS certificate. Instead, a listener with an empty ``spec.listeners[].hostname``
field matches all hostnames, effectively serving as a fallback for that specific protocol and port.

In this example, we will deploy a simple HTTP service and expose it via the Cilium Gateway API.

We will use the ``bookinfo`` sample application from the Istio project.

.. include:: ../demo-app.rst

.. include:: ../tls-cert.rst

Deploy the Gateway and HTTPRoutes
=================================

In this example, a single certificate serves all incoming TLS connections, which are
then routed to the appropriate backend based on the hostnames defined in the HTTPRoutes.

.. literalinclude:: ../../../../examples/kubernetes/gateway/https-default-tls-certificate.yaml
     :language: yaml

Apply the configuration:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/https-default-tls-certificate.yaml

Once the Gateway and HTTPRoutes are deployed, you can find external IP address in Gateway, and ensure hostnames are valid in HTTPRoute.

.. code-block:: shell-session

    $ kubectl get gateway tls-gateway
    NAME          CLASS    ADDRESS          PROGRAMMED   AGE
    tls-gateway   cilium   172.18.255.200   True         27m

    $ kubectl get httproute bookinfo hipstershop
    NAME          HOSTNAMES                      AGE
    bookinfo      ["bookinfo.cilium.rocks"]      27m
    hipstershop   ["hipstershop.cilium.rocks"]   27m

Make HTTPS Requests
===================

.. tabs::

    .. group-tab:: Self-signed Certificate

        By specifying the CA's certificate in a curl request, you can indicate that you trust certificates signed by that CA.

        .. code-block:: shell-session

            $ curl --cacert minica.pem -v https://bookinfo.cilium.rocks/details/1 --resolve bookinfo.cilium.rocks:443:172.18.255.200
            $ curl --cacert minica.pem -v https://hipstershop.cilium.rocks/ --resolve hipstershop.cilium.rocks:443:172.18.255.200
            ...
            *   subjectAltName: "bookinfo.cilium.rocks" matches cert's "bookinfo.cilium.rocks"
            * SSL certificate verified via OpenSSL.

        You should see no warning messages, as the TLS certificate was issued for the requested hostnames.

        The following request demonstrates that when accessing the service via an IP address, the client does not provide an SNI header.
        This typically occurs when Cilium acts as a backend for a load balancer or proxy that uses an IP address to establish connections.
        Despite the lack of SNI, a TLS connection is still established using the default certificate.
        Note that since the certificate's hostname will not match the IP address, we use the ``-k`` flag in curl to bypass validation.

        Subsequent routing to the correct backend is then determined by the ``Host`` HTTP header, which we provide explicitly in this example.

        .. code-block:: shell-session

            $ curl -H "Host: hipstershop.cilium.rocks" -k -v https://172.18.255.200/
            ...
            *  SSL certificate verification failed, continuing anyway!
            * Established connection to 172.18.255.200 (172.18.255.200 port 443) from 10.244.0.52 port 42458

        By specifying ``-v`` in the curl request, you can see that the TLS handshake was successful.

    .. group-tab:: cert-manager

        By specifying the CA's certificate in a curl request, you can indicate that you trust certificates signed by that CA.

        .. code-block:: shell-session

            $ curl --cacert cm-cert.pem -v https://bookinfo.cilium.rocks/details/1 --resolve bookinfo.cilium.rocks:443:172.18.255.200
            $ curl --cacert cm-cert.pem -v https://hipstershop.cilium.rocks/ --resolve hipstershop.cilium.rocks:443:172.18.255.200
            ...
            *   subjectAltName: "bookinfo.cilium.rocks" matches cert's "bookinfo.cilium.rocks"
            * SSL certificate verified via OpenSSL.

        You should see no warning messages, as the TLS certificate was issued for the requested hostnames.

        The following request demonstrates that when accessing the service via an IP address, the client does not provide an SNI header.
        This typically occurs when Cilium acts as a backend for a load balancer or proxy that uses an IP address to establish connections.
        Despite the lack of SNI, a TLS connection is still established using the default certificate.
        Note that since the certificate's hostname will not match the IP address, we use the ``-k`` flag in curl to bypass validation.

        Subsequent routing to the correct backend is then determined by the ``Host`` HTTP header, which we provide explicitly in this example.

        .. code-block:: shell-session

            $ curl -H "Host: hipstershop.cilium.rocks" -k -v https://172.18.255.200/
            ...
            *  SSL certificate verification failed, continuing anyway!
            * Established connection to 172.18.255.200 (172.18.255.200 port 443) from 10.244.0.52 port 42458

        By specifying ``-v`` in the curl request, you can see that the TLS handshake was successful.
