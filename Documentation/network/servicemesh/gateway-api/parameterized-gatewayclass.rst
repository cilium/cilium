.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_parametrized_gatewayclass:

*******************************
GatewayClass Parameters Support
*******************************

The default behavior of Gateway API can be modified by providing parameters to the GatewayClass. The parameters are
defined in the GatewayClass and can be referenced in the Gateway object. The GatewayClass parameters are defined in the
``CiliumGatewayClassConfig`` CRD.

The demo application is from the ``bookinfo`` demo microservices app from
the Istio project.

.. include:: ../demo-app.rst

Deploy the Cilium Gateway with customized parameters
====================================================

In this example, we will deploy a Cilium Gateway with ``NodePort`` service instead of the default ``LoadBalancer`` type.

.. literalinclude:: ../../../../examples/kubernetes/gateway/gateway-with-parameters.yaml
     :language: yaml

Apply the configuration:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/gateway-with-parameters.yaml

Once the Gateway is deployed, you can access the service using via NodePort service.

.. code-block:: shell-session

    $ kubectl  services cilium-gateway-nodeport-gateway
    NAME                              TYPE       CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE
    cilium-gateway-nodeport-gateway   NodePort   10.96.45.118   <none>        80:30493/TCP   11s

    # Sending some traffic to nodeport service, after ssh to one of the kubernetes node
    root@kind-worker:/# curl http://localhost:30493/details/1
    {"id":1,"author":"William Shakespeare","year":1595,"type":"paperback","pages":200,"publisher":"PublisherA","language":"English","ISBN-10":"1234567890","ISBN-13":"123-1234567890"}root@kind-worker:/#

Reference
=========

The full list of supported parameters can be found in the ``CiliumGatewayClassConfig`` CRD.

.. warning::
    The ``CiliumGatewayClassConfig`` CRD is an alpha API, and per the standard Kubernetes object versioning,
    is subject to breaking changes. If you use it, please read the release notes carefully in case there are
    breaking changes. Please also consider reporting both your usage of the CRD and any issues either on Github or
    in Slack.

.. literalinclude:: ../../../../examples/crds/v2alpha1/ciliumgatewayclassconfigs.yaml
     :language: yaml
