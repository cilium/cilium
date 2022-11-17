.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress_grpc:

********************
Ingress gRPC Example
********************

The example ingress configuration in ``grpc-ingress.yaml`` shows how to route
gRPC traffic to backend services.

Deploy the Demo App
*******************

For this demo we will use `GCP's microservices demo app <https://github.com/GoogleCloudPlatform/microservices-demo>`_.

.. code-block:: shell-session

    $ kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml

Since gRPC is binary-encoded, you also need the proto definitions for the gRPC
services in order to make gRPC requests. Download this for the demo app:

.. code-block:: shell-session

    $ curl -o demo.proto https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/pb/demo.proto


Deploy GRPC Ingress
*******************

You'll find the example Ingress definition in ``examples/kubernetes/servicemesh/grpc-ingress.yaml``.

.. literalinclude:: ../../../examples/kubernetes/servicemesh/grpc-ingress.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/grpc-ingress.yaml

This defines paths for requests to be routed to the ``productcatalogservice`` and
``currencyservice`` microservices.

Just as in the previous HTTP Ingress Example, this creates a LoadBalancer service,
and it may take a little while for your cloud provider to provision an external
IP address.

.. code-block:: shell-session

    $ kubectl get ingress
    NAME           CLASS    HOSTS   ADDRESS         PORTS   AGE
    grpc-ingress   cilium   *       10.111.109.99   80      3s


Make gRPC Requests to Backend Services
**************************************

To issue client gRPC requests you can use `grpcurl <https://github.com/fullstorydev/grpcurl#binaries>`_.

.. code-block:: shell-session

    $ GRPC_INGRESS=$(kubectl get ingress grpc-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    # To access the currency service:
    $ grpcurl -plaintext -proto ./demo.proto $GRPC_INGRESS:80 hipstershop.CurrencyService/GetSupportedCurrencies
    #To access the product catalog service:
    $ grpcurl -plaintext -proto ./demo.proto $GRPC_INGRESS:80 hipstershop.ProductCatalogService/ListProducts
