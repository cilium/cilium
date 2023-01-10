.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_http:

************
HTTP Example
************

In this example, we will deploy a simple HTTP service and expose it to the
Cilium Gateway API.

The demo application is from the ``bookinfo`` demo microservices app from
the Istio project.

.. include:: ../demo-app.rst

Deploy the Cilium Gateway
=========================

You'll find the example Gateway and HTTPRoute definition in ``basic-http.yaml``.

.. literalinclude:: ../../../../examples/kubernetes/gateway/basic-http.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/basic-http.yaml

The above example creates a Gateway named ``my-gateway`` that listens on port 80.
Two routes are defined, one for ``/details`` to the ``details`` service, and
one for ``/`` to the ``productpage`` service.

Your cloud provider will automatically provision an external IP address for the
gateway, but it may take up to 20 minutes.

.. code-block:: shell-session

    $ kubectl get gateway my-gateway
    NAME         CLASS    ADDRESS        READY   AGE
    my-gateway   cilium   10.100.26.37   True    2d7h

.. Note::

    Some providers e.g. EKS use a fully-qualified domain name rather than an IP address.

Make HTTP Requests
==================

Now that the Gateway is ready, you can make HTTP requests to the services.

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway my-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail -s http://"$GATEWAY"/details/1 | jq
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
    $ curl -v -H 'magic: foo' http://"$GATEWAY"\?great\=example
    ...
    <!DOCTYPE html>
    <html>
      <head>
        <title>Simple Bookstore App</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="static/bootstrap/css/bootstrap.min.css">

    <!-- Optional theme -->
    <link rel="stylesheet" href="static/bootstrap/css/bootstrap-theme.min.css">

      </head>
      <body>


    <p>
        <h3>Hello! This is a simple bookstore application consisting of three services as shown below</h3>
    </p>

    <table class="table table-condensed table-bordered table-hover"><tr><th>name</th><td>http://details:9080</td></tr><tr><th>endpoint</th><td>details</td></tr><tr><th>children</th><td><table class="table table-condensed table-bordered table-hover"><tr><th>name</th><th>endpoint</th><th>children</th></tr><tr><td>http://details:9080</td><td>details</td><td></td></tr><tr><td>http://reviews:9080</td><td>reviews</td><td><table class="table table-condensed table-bordered table-hover"><tr><th>name</th><th>endpoint</th><th>children</th></tr><tr><td>http://ratings:9080</td><td>ratings</td><td></td></tr></table></td></tr></table></td></tr></table>

    <p>
        <h4>Click on one of the links below to auto generate a request to the backend as a real user or a tester
        </h4>
    </p>
    <p><a href="/productpage?u=normal">Normal user</a></p>
    <p><a href="/productpage?u=test">Test user</a></p>



    <!-- Latest compiled and minified JavaScript -->
    <script src="static/jquery.min.js"></script>

    <!-- Latest compiled and minified JavaScript -->
    <script src="static/bootstrap/js/bootstrap.min.js"></script>

      </body>
    </html>
