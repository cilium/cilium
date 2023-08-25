.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_header:

*****************************
HTTP Header Modifier Examples
*****************************

The Gateway can modify the headers of HTTP requests from clients. 

.. include:: ../echo-app.rst

Deploy the Cilium Gateway
=========================

HTTP header modification is the process of adding, removing, or modifying HTTP headers in incoming requests.
To configure HTTP header modification, define a Gateway object with one or more HTTP filters. Each filter specifies a specific modification to make to incoming requests, such as adding a custom header or modifying an existing header.

To add a header to a HTTP request, use a filter of the type ``RequestHeaderModifier`` with the ``add`` action and the name and value of the header.

You can find an example Gateway and HTTPRoute definition in ``request-header.yaml``:

.. literalinclude:: ../../../../examples/kubernetes/gateway/request-header.yaml

This example adds a header named ``my-header-name`` with the ``my-header-value`` value.

Deploy the Gateway and the HTTPRoute:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/request-header.yaml

The preceding kubectl command creates a Gateway named ``cilium-gw`` that listens on port 80.

.. code-block:: shell-session

    $ kubectl get gateway cilium-gw
    NAME        CLASS    ADDRESS          PROGRAMMED   AGE
    cilium-gw   cilium   172.18.255.200                8s

.. Note::

    Some providers like EKS use a fully-qualified domain name rather than an IP address.

Modify incoming HTTP Requests 
=============================

Now that the Gateway is ready, you can make HTTP requests.

.. code-block:: shell-session

    $ curl -s http://$GATEWAY/add-a-request-header | grep -A 6 "Request Headers"
    Request Headers:
        accept=*/*  
        host=172.18.255.200  
        my-header-name=my-header-value  
        user-agent=curl/7.81.0  
        x-forwarded-proto=http
        x-request-id=61a72702-3dfa-4bc3-a21c-7544ef36af7b

If the curl succeeds, you can see the HTTP Header from the incoming request in the body of the response sent back from the echo server. You can also see that the Gateway added the header.

You can also remove headers with the ``remove`` keyword and a list of header names.

.. code-block:: shell-session

    filters
    - type: RequestHeaderModifier
      requestHeaderModifier:
        remove: ["x-request-id"]

Notice that the ``x-request-id`` header is removed when you add the ``remove-a-request-header`` prefix match to the filter:

.. code-block:: shell-session

    $ curl --fail -s http://$GATEWAY/remove-a-request-header | grep -A 6 "Request Headers"
    Request Headers:
        accept=*/*  
        host=172.18.255.200  
        user-agent=curl/7.81.0  
        x-forwarded-proto=http  

To edit an existing header, use the ``set`` action to specify the value of the header to modify as well as the new header value to set.

.. code-block:: shell-session

    filters:
    - type: RequestHeaderModifier
      requestHeaderModifier:
        set:
        - name: x-request-id
          value: set-cilium-header-value

Notice that the ``x-request-id`` header is changed when you add the ``edit-a-request-header`` prefix match to the filter:

.. code-block:: shell-session

    $ curl -s http://$GATEWAY/edit-a-request-header | grep -A 6 "Request Headers"
    Request Headers:
        accept=*/*  
        host=172.18.255.200  
        user-agent=curl/7.81.0  
        x-forwarded-proto=http  
        x-request-id=set-cilium-header-value