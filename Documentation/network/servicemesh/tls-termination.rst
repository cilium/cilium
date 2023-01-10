.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress_tls:

************************************
Ingress Example with TLS Termination
************************************

This example builds on the HTTP and gRPC ingress examples, adding TLS
termination.

.. literalinclude:: ../../../examples/kubernetes/servicemesh/tls-ingress.yaml

.. include:: tls-cert.rst

Deploy the Ingress
==================

The Ingress configuration for this demo provides the same routing as those demos
but with the addition of TLS termination.


.. tabs::

    .. group-tab:: Self-signed Certificate

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/tls-ingress.yaml

    .. group-tab:: Cert Manager

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/tls-ingress.yaml

        To tell cert-manager that this Ingress needs a certificate, annotate the
        Ingress with the name of the CA issuer we previously created:

        .. code-block:: shell-session

            $ kubectl annotate ingress tls-ingress cert-manager.io/issuer=ca-issuer

        This creates a Certificate object along with a Secret containing the TLS
        certificate.

        .. code-block:: shell-session

            $ kubectl get certificate,secret demo-cert
            NAME                                    READY   SECRET      AGE
            certificate.cert-manager.io/demo-cert   True    demo-cert   33m
            NAME               TYPE                DATA   AGE
            secret/demo-cert   kubernetes.io/tls   3      33m

External IP address will be shown up in Ingress

.. code-block:: shell-session

    $ kubectl get ingress
    NAME          CLASS    HOSTS                                            ADDRESS        PORTS     AGE
    tls-ingress   cilium   hipstershop.cilium.rocks,bookinfo.cilium.rocks   35.195.24.75   80, 443   6m5s

In this Ingress configuration, the host names ``hipstershop.cilium.rocks`` and
``bookinfo.cilium.rocks`` are specified in the path routing rules. The client
needs to specify which host it wants to access. This can be achieved by
editing your local ``/etc/hosts``` file. (You will almost certainly need to be
superuser to edit this file.) Add entries using the IP address
assigned to the ingress service, so your file looks something like this:

.. code-block:: shell-session

    $ sudo perl -ni -e 'print if !/\.cilium\.rocks$/d' /etc/hosts; sudo tee -a /etc/hosts \
      <<<"$(kubectl get ing tls-ingress -o=jsonpath='{.status.loadBalancer.ingress[0].ip}') bookinfo.cilium.rocks hipstershop.cilium.rocks"


Make HTTPS Requests
===================


.. tabs::

    .. group-tab:: Self-signed Certificate

        By specifying the CA's certificate on a curl request, you can say that you trust certificates
        signed by that CA.

        .. code-block:: shell-session

            $ curl --cacert minica.pem -v https://bookinfo.cilium.rocks/details/1

        If you prefer, instead of supplying the CA you can specify ``-k`` to tell the
        curl client not to validate the server's certificate. Without either, you
        will get an error that the certificate was signed by an unknown authority.

        Specifying -v on the curl request, you can see that the TLS handshake took
        place successfully.

        Similarly you can specify the CA on a gRPC request like this:

        .. code-block:: shell-session

            # Download demo.proto file if you have not done before
            $ curl -o demo.proto https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/pb/demo.proto
            $ grpcurl -proto ./demo.proto -cacert minica.pem hipstershop.cilium.rocks:443 hipstershop.ProductCatalogService/ListProducts

    .. group-tab:: Cert Manager

        .. code-block:: shell-session

            $ curl https://bookinfo.cilium.rocks/details/1

        Similarly you can specify the CA on a gRPC request like this:

        .. code-block:: shell-session

            grpcurl -proto ./demo.proto -cacert minica.pem hipstershop.cilium.rocks:443 hipstershop.ProductCatalogService/ListProducts

.. Note::

    See the gRPC Ingress example if you don't already have the ``demo.proto`` file downloaded.

You can also visit https://bookinfo.cilium.rocks in your browser. The browser
might warn you that the certificate authority is unknown but if you proceed past
this, you should see the bookstore application home page.

Note that requests will time out if you don't specify ``https://``.
