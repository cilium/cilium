.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_backendtlspolicy:

************************
BackendTLSPolicy Example
************************

This example will use the ``echo-server`` sample application to demonstrate how to use BackendTLSPolicy.

You will need ``mkcert`` tool to generate certificates. See the tool's `upstream site <github-mkcert>`_ for details.

This task uses a self-signed CA, and is only for demonstration purposes.

Deploy ``echo-server``
======================

Apply the following to deploy the ``echo-server``.

.. literalinclude:: ../../../../examples/kubernetes/servicemesh/echo-server.yaml
   :language: yaml

Apply the following to create a Gateway and HTTPRoute for the ``echo-server``:

.. literalinclude:: ../../../../examples/kubernetes/servicemesh/echo-server-gatewaypi-httproute.yaml
   :language: yaml

Test the sample application:

.. code-block:: shell-session

   $ curl -v --resolve www.example.com:80:<GATEWAY_IP_ADDRESS> http://www.example.com/get

The curl command will return the information about the request. It should look like the following:

.. code-block:: json 

     {
      "path": "/get",
      "host": "www.example.com",
      "method": "GET",
      "proto": "HTTP/1.1",
      "headers": {
       "Accept": [
        "*/*"
       ],
       "User-Agent": [
        "curl/8.20.0"
       ],
       "X-Envoy-Internal": [
        "true"
       ],
       "X-Forwarded-For": [
        "172.19.0.1"
       ],
       "X-Forwarded-Proto": [
        "http"
       ],
       "X-Request-Id": [
        "bb913f3e-7538-4873-88e4-25499fe5b3ff"
       ]
      },
      "namespace": "default",
      "ingress": "",
      "service": "",
      "pod": "backend-86c6c76f-ptczl"
     }

Generate demo TLS Certificates
==============================

Generate the certificates and keys for example.com.

First, create the root certificate.

.. code-block:: shell-session

   mkcert www.example.com

This will output the certificate and key in the current directory.

Create the secret and configmap in your cluster
===============================================

Store the cert and key into a Kubernetes Secret.

.. code-block:: shell-session

   kubectl create secret tls example-cert --key=www.example.com-key.pem --cert=www.example.com.pem

Create a configmap in your cluster.

.. code-block:: shell-session

   kubectl create configmap example-ca --from-file=ca.crt=www.example.com.pem

Setup TLS between gateway and backend
=====================================

Patch the backend deployment to enable TLS. The following command mounts the TLS certificate secret into the backend container as a volume.

.. code-block:: shell-session

   kubectl patch deployment backend --type=json --patch '
  - op: add
    path: /spec/template/spec/containers/0/volumeMounts
    value:
    - name: secret-volume
      mountPath: /etc/secret-volume
  - op: add
    path: /spec/template/spec/volumes
    value:
    - name: secret-volume
      secret:
        secretName: example-cert
        items:
        - key: tls.crt
          path: crt
        - key: tls.key
          path: key
  - op: add
    path: /spec/template/spec/containers/0/env/-
    value:
      name: TLS_SERVER_CERT
      value: /etc/secret-volume/crt
  - op: add
    path: /spec/template/spec/containers/0/env/-
    value:
      name: TLS_SERVER_PRIVKEY
      value: /etc/secret-volume/key
  '

Configure the backend service to expose port 443. Apply the following to update ``backend`` service the ports to listen on 443:

.. code-block:: yaml

   apiVersion: v1
   kind: Service
   metadata:
     labels:
       app: backend
       service: backend
     name: backend
   spec:
     selector:
       app: backend
     ports:
     - name: https
       port: 443
       protocol: TCP
       targetPort: 8443

Create the BackendTLSPolicy to tell the Cilium Gateway to use a TLS connection with the backend.

.. code-block:: yaml

   apiVersion: gateway.networking.k8s.io/v1
   kind: BackendTLSPolicy
   metadata:
     name: enable-backend-tls
     namespace: default
   spec:
     targetRefs:
     - group: ''
       kind: Service
       name: backend
       sectionName: https
     validation:
       caCertificateRefs:
       - name: example-ca
         group: ''
         kind: ConfigMap
       hostname: www.example.com

Patch the HTTPRoute backend reference, so that it uses the correct port edited in the backend service.

.. code-block:: shell-session

   kubectl patch HTTPRoute backend --type=json --patch '
    - op: replace
      path: /spec/rules/0/backendRefs/0/port
      value: 443
   '

Testing the backend TLS connection
==================================

Try to curl the service through the Gateway.

.. code-block:: shell-session

   $ curl -vI --resolve "www.example.com:80:<YOUR_GATEWAY_EXTERNAL_IP>" http://www.example.com:80/get

You should receive back a ``200 OK`` response. The curl response will look similar to the earlier curl response, but note that the response also demonstrates the TLS encryption details:

.. code-block:: json

   { 
     "tls": {
      "version": "TLSv1.3",
      "serverName": "www.example.com",
      "negotiatedProtocol": "http/1.1",
      "cipherSuite": "TLS_AES_128_GCM_SHA256"
     }
    } 


.. LINKS
.. _github-mkcert: https://github.com/FiloSottile/mkcert
