.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress_and_network_policy:

**********************************
Ingress and Network Policy Example
**********************************

This example uses the same configuration as the base HTTP Ingress example, using
the ``bookinfo`` demo microservices app from the Istio project, and then adds
CiliumNetworkPolicy on the top.

.. include:: demo-app.rst

.. _gs_basic_ingress_policy:

.. include:: basic-ingress.rst


Confirm that your Ingress is working:

.. code-block:: shell-session

    $ HTTP_INGRESS=$(kubectl get ingress basic-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    $ curl --fail -s http://"$HTTP_INGRESS"/details/1 | jq
    {
      "id": 1,
      "author": "William Shakespeare",
      "year": 1595,
      "type": "paperback",
      "pages": 200,
      "publisher": "PublisherA",
      "language": "English",
      "ISBN-10": "1234567890",
      "ISBN-13": "123-1234567890"
    }

.. include:: external-ingress-policy.rst

.. include:: default-deny-ingress-policy.rst
