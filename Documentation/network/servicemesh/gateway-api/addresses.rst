.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


Gateway API Addresses Support
*****************************

Cilium Gateway supports `Addresses <https://gateway-api.sigs.k8s.io/api-types/gateway/?h=addresses>`__ provided by the Gateway API specification.
The ``spec.addresses`` field is used to specify the IP address of the gateway.

.. note::
   
      The feature only supports IPAddress type of addresses, and works with the LB-IPAM. 
      Please see :ref:`lb_ipam` for more information.


.. code-block:: yaml

    apiVersion: gateway.networking.k8s.io/v1
    kind: Gateway
    metadata:
      name: my-gateway
    spec:
      addresses:
      - type: IPAddress
        value: 172.18.0.140
      gatewayClassName: cilium
      listeners:
      - allowedRoutes:
          namespaces:
            from: Same
        name: web-gw
        port: 80
        protocol: HTTP


The output of the above configuration will be:

.. code-block:: shell-session

    $ kubectl get gateway my-gateway
    NAME         CLASS    ADDRESS        PROGRAMMED   AGE
    my-gateway   cilium   172.18.0.140   True         2d7h



If you are already using the ``io.cilium/lb-ipam-ips`` in the ``spec.infrastructure.annotations`` to 
specify the IP, the ``spec.addresses`` field will be ignored.


.. code-block:: yaml

    apiVersion: gateway.networking.k8s.io/v1
    kind: Gateway
    metadata:
      name: my-gateway
    spec:
      infrastructure:
        annotations:
          io.cilium/lb-ipam-ips: "172.18.0.141"
      addresses: # This will be ignored
      - type: IPAddress
        value: 172.18.0.140 
      gatewayClassName: cilium
      listeners:
      - allowedRoutes:
          namespaces:
            from: Same
        name: web-gw
        port: 80
        protocol: HTTP

The output of the above configuration will be:

.. code-block:: shell-session

    $ kubectl get gateway my-gateway
    NAME         CLASS    ADDRESS        PROGRAMMED   AGE
    my-gateway   cilium   172.18.0.141   True         2d7h


.. note::

    At a future date the use of the ``io.cilium/lb-ipam-ips`` will be deprecated, and then after that, this annotation will be 
    ignored if no ``spec.addresses`` are set. In both cases, warning logs will be added to the Cilium agent logs, and a 
    warning Condition will be placed on the Gateway.