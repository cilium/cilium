.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress_http:

********************
Ingress HTTP Example
********************

The example ingress configuration routes traffic to backend services from the
``bookinfo`` demo microservices app from the Istio project.

.. include:: demo-app.rst

.. _gs_basic_ingress:

.. include:: basic-ingress.rst

Make HTTP Requests
==================

Check (with ``curl`` or in your browser) that you can make HTTP requests to that
external address. The ``/`` path takes you to the home page for the bookinfo
application.

From outside the cluster you can also make requests directly to the ``details``
service using the path ``/details``. But you can't directly access other URL paths
that weren't defined in ``basic-ingress.yaml``.

For example, you can get JSON data from a request to  ``<address>/details/1`` and
get back some data, but you will get a 404 error if you make a request to ``<address>/ratings``.

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

