.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_grpc:

*************
gRPC Example
*************

This example demonstrates how to set up a Gateway that terminates TLS traffic and
routes requests to a gRPC service (i.e. using HTTP/2). In order for this example to
work, ALPN support needs to be enabled with the Helm flag ``gatewayAPI.enableAlpn``
set to true. This enables clients to request HTTP/2 through the TLS negotiation.

.. literalinclude:: ../../../../examples/kubernetes/gateway/grpc-tls-termination.yaml
     :language: yaml

.. tabs::

    .. group-tab:: Self-signed Certificate

        For demonstration purposes we will use a TLS certificate signed by a made-up,
        `self-signed <https://cert-manager.io/docs/faq/terminology/#what-does-self-signed-mean-is-my-ca-self-signed>`_
        certificate authority (CA). One easy way to do this is with `mkcert <https://github.com/FiloSottile/mkcert>`_.
        We want a certificate that will validate ``grpc-echo.cilium.rocks``, as these are the host names used in this example.

        .. code-block:: shell-session

            $ mkcert bookinfo.cilium.rocks hispter.cilium.rocks
            Created a new local CA 💥
            Note: the local CA is not installed in the system trust store.
            Run "mkcert -install" for certificates to be trusted automatically ⚠

            Created a new certificate valid for the following names 📜
             - "grpc-echo.cilium.rocks"

            The certificate is at "./grpc-echo.cilium.rocks.pem" and the key at "./grpc-echo.cilium.rocks-key.pem" ✅

            It will expire on 28 September 2027 🗓

        Create a Kubernetes secret with this demo key and certificate:

        .. code-block:: shell-session

            $ kubectl create secret tls grpc-certificate --key=grpc-echo.cilium.rocks-key.pem --cert=grpc-echo.cilium.rocks.pem

    .. group-tab:: cert-manager

        Let us install cert-manager:

        .. code-block:: shell-session

            $ helm repo add jetstack https://charts.jetstack.io
            $ helm install cert-manager jetstack/cert-manager --version v1.16.2 \
                --namespace cert-manager \
                --set crds.enabled=true \
                --create-namespace \
                --set config.apiVersion="controller.config.cert-manager.io/v1alpha1" \
                --set config.kind="ControllerConfiguration" \
                --set config.enableGatewayAPI=true

        Now, create a CA Issuer:

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/ca-issuer.yaml

Deploy the Gateway and GRPCRoute
================================

This sets up a simple gRPC echo server and a Gateway to expose it.

.. tabs::

    .. group-tab:: Self-signed Certificate

        We already created the certificate Secret in the previous step, so
        we can just create the resources:

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/grpc-tls-termination.yaml

    .. group-tab:: cert-manager

        .. parsed-literal::

            $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/grpc-tls-termination.yaml

        To tell cert-manager that this Gateway needs a certificate, annotate the
        Gateway with the name of the CA issuer we previously created:

        .. code-block:: shell-session

            $ kubectl annotate gateway tls-gateway cert-manager.io/issuer=ca-issuer

        This creates a Certificate object along with a Secret containing the TLS
        certificate.

        .. code-block:: shell-session

            $ kubectl get certificate,secret grpc-certificate
            NAME                                           READY   SECRET             AGE
            certificate.cert-manager.io/grpc-certificate   True    grpc-certificate   83s
            NAME                      TYPE                DATA   AGE
            secret/grpc-certificate   kubernetes.io/tls   3      78s

External IP address will be shown up in Gateway. Also, the host names should show
up in related HTTPRoutes.

.. code-block:: shell-session

    $ kubectl get gateway tls-gateway
    NAME          CLASS    ADDRESS         PROGRAMMED   AGE
    tls-gateway   cilium   10.104.247.23   True         29s

    $ kubectl get grpcroutes
    NAME         HOSTNAMES   AGE
    grpc-route               116s

Update ``/etc/hosts`` with the host names and IP address of the Gateway:

.. code-block:: shell-session

    $ sudo perl -ni -e 'print if !/\.cilium\.rocks$/d' /etc/hosts; sudo tee -a /etc/hosts \
      <<<"$(kubectl get gateway tls-gateway -o jsonpath='{.status.addresses[0].value}') grpc-echo.cilium.rocks"

Make gRPC Requests
===================

We can use the `grpcurl <https://github.com/fullstorydev/grpcurl>`_ cli tool to verify
that the service works correctly. The echo server used in this example will respond
with information about the HTTP/2 request the client made.

.. tabs::

    .. group-tab:: Self-signed Certificate

        By specifying the CA's certificate on a curl request, you can say that you 
        trust certificates signed by that CA.

        .. code-block:: shell-session

            $ grpcurl -cacert ~/.local/share/mkcert/rootCA.pem grpc-echo.cilium.rocks:443 proto.EchoTestService/Echo

        If you prefer, instead of supplying the CA you can specify ``-insecure`` to
        tell the curl client not to validate the server's certificate. Without
        either, you will get an error that the certificate was signed by an unknown
        authority.

    .. group-tab:: cert-manager

        .. code-block:: shell-session

            $ grpcurl grpc-echo.cilium.rocks:443 proto.EchoTestService/Echo
            {
              "message": "Host=grpc-echo.cilium.rocks:443\nRequestHeader=:authority:grpc-echo.cilium.rocks:443\nRequestHeader=content-type:application/grpc\nRequestHeader=grpc-accept-encoding:gzip\nRequestHeader=x-forwarded-proto:https\nRequestHeader=x-request-id:f7889cda-08b2-45cf-9329-833633ae8d9c\nRequestHeader=user-agent:grpcurl/dev-build (no version set) grpc-go/1.61.0\nRequestHeader=x-forwarded-for:172.22.0.7\nRequestHeader=x-envoy-internal:true\nStatusCode=200\nServiceVersion=\nServicePort=7070\nIP=10.244.1.101\nProto=GRPC\nEcho=\nHostname=grpc-echo-6879fc6969-2kh6r\n"
            }
