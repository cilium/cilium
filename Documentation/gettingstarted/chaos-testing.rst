.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _chaos_testing:

********************************
Chaos testing HTTP/REST services
********************************

This tutorial walks you through examples of applying chaos testing to your
REST-based services using the ``chaos`` Cilium Go extension of Envoy.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

Install Cilium
==============

Use any of the :ref:`gs_install` guides to install Cilium or follow the
:ref:`gs_minikube` guide to get Cilium up and running quickly.

Deploy Example Services
=======================

For the purpose of this tutorial, we'll be using httpbin and curl to simulate services
but you can modify all of the examples in this tutorial to your own services as
well.

.. parsed-literal::

    kubectl apply -f \ |SCM_WEB|\/examples/chaos-testing/httpbin.yaml
    kubectl apply -f \ |SCM_WEB|\/examples/chaos-testing/curl.yaml

Verify that the pods are running:

::

    kubectl get pods
    NAME                       READY   STATUS    RESTARTS   AGE
    curl-9f5cdf758-nqvcb       1/1     Running   0          24h
    httpbin-6fbbf9448c-4pbpj   1/1     Running   0          24h

Capability Overview
===================

A common tool to practice chaos testing is to apply fault injection between
services. The purpose of fault injection is to simulate failures without
requiring services themselves. The following lists the capabilities of Cilium's
``chaos`` Envoy plugin which consists of filters and actions.

Filters
-------

Filters are used to limit actions to a subset of HTTP requests and HTTP
responses. If multiple filters are specified in a rule, all filters must match:

probability:
   Actions will apply based on the specified probability (0..1).
   
   Example:
   ``probability: 0.5``

method:
    HTTP request method must match specified name

    Example:
    ``method: GET``

path:
   HTTP path must match the specified regular expression

   Example:
   ``path: ^/foo/.*/bar``

status-code:
   The HTTP response code must match the specified number

   Example:
   ``status-code: 200``

Actions
-------

Once a filter matches, all actions defined in the filter are applied. In order
for a response action to be performed, the filters for both request and
response are required to match.

delay-request:
   Delay the HTTP request for the specified duration.
   `time.ParseDuration() <https://golang.org/pkg/time/#ParseDuration>`_ is used
   to parse the duration. Using this option will add a HTTP header to the
   request in the form of ``X-Cilium-Delay: Delayed for <duration>`.

   Example:
   ``delay-request: 200ms``

delay-response::
   Delay the HTTP response for the specified duration.
   `time.ParseDuration() <https://golang.org/pkg/time/#ParseDuration>`_ is used
   to parse the duration. Using this option will add a HTTP header to the response
   in the form of ``X-Cilium-Delay: Delayed for <duration>`1

   Example:
   ``delay-response: 100ms``

rewrite-status:
   Rewrites the status code and text of the HTTP response,

   Example:
   ``rewrite-status: 403 FORBIDDEN``

add-request-headers:
   Add additional HTTP headers to the request

   *Example:*
   ``add-request-headers: X-My-Header-1=Value,X-My-Header-2=Value``

add-response-headers:
   Add additional HTTP headers to the response

   Example:
   ``add-request-headers: X-My-Header-1=Value,X-My-Header-2=Value``

Examples
========

Delay HTTP requests
-------------------

Delay all requests to httpbin by one second with a probability of 50%

.. code:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "chaos-1"
    specs:
      - endpointSelector:
          matchLabels:
            app: httpbin
        ingress:
        - toPorts:
          - ports:
            - port: "8000"
              protocol: TCP
            rules:
              l7proto: chaos
              l7:
              - probability: "0.5"
                delay-request: 1s

**Output:**

::

    kubectl exec -ti curl-9f5cdf758-nqvcb -- curl httpbin:8000/headers
    {
      "headers": {
        "Accept": "*/*",
        "Host": "10.15.136.75:8000",
        "User-Agent": "curl/7.35.0",
        "X-Cilium-Delay": "Delayed request for 1s"
      }
    }

Simulate service failures
-------------------------

Simulate service failure by returning a 504 HTTP response code with a
probability of 80%:

.. code:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "chaos-1"
    specs:
      - endpointSelector:
          matchLabels:
            app: httpbin
        ingress:
        - toPorts:
          - ports:
            - port: "8000"
              protocol: TCP
            rules:
              l7proto: chaos
              l7:
              - probability: "0.8"
                rewrite-status: 504 Application Error

**Output:**

::

    kubectl exec -ti curl-9f5cdf758-nqvcb -- curl -I httpbin:8000
    HTTP/1.1 504 Application Error
    Connection: close
    Content-Length: 11602
    Access-Control-Allow-Credentials: true
    Access-Control-Allow-Origin: *
    Content-Type: text/html; charset=utf-8
    Date: Thu, 16 May 2019 18:31:14 GMT
    Server: gunicorn/19.6.0


.. note::
    Remember to run ``curl`` with the option ``-I`` to see the returned
    response code.


Limit on HTTP path and method
-----------------------------

Method and path filters can be combined to limit addition of additional headers
to requests with the method ``GET`` and path matching the regular expression
``^/headers``

.. code:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "chaos-1"
    specs:
      - endpointSelector:
          matchLabels:
            app: httpbin
        ingress:
        - toPorts:
          - ports:
            - port: "8000"
              protocol: TCP
            rules:
              l7proto: chaos
              l7:
              - method: GET
                path: ^/headers
                add-request-headers: X-Custom=Value

**Output:**

::

    kubectl exec -ti curl-9f5cdf758-nqvcb -- curl httpbin:8000/headers
    {
      "headers": {
        "Accept": "*/*",
        "Host": "10.15.136.75:8000",
        "User-Agent": "curl/7.35.0",
        "X-Custom": "Value"
      }
    }


Visibility
==========

In order to gain visibility into what is going on, ``cilium monitor`` can be used:

::

    kubectl -n kube-system exec -ti cilium-dzvs9 -- cilium monitor -t l7
    [...]
    <- Request http from 0 ([k8s:app=curl k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default]) to 444 ([k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default k8s:app=httpbin k8s:io.cilium.k8s.policy.cluster=default k8s:version=v1]), identity 64515->42470, verdict Forwarded method:GET url:/headers length:0


.. note::
   ``cilium monitor`` operates at the scope of a node, you need to run the
   monitor on the node of the source or destination service.


Custom Chaos Testing Logic
==========================

The chaos-testing plugin is written in Go and uses the standard ``net/http``
framework which makes it easy to extend and capable of plugging arbitrary HTTP
request handlers into it:

**proxylib/chaostesting/chaostesting.go:**

.. code:: go

    func (c *ChaosRule) matchRequest(req *http.Request) bool {
            log.Debugf("Matches() called on HTTP request, rule: %#v", c)

            if c.probability != float64(0) {
                    if c.probabilitySource.Float64() > c.probability {
                            return false
                    }
            }
    [..]

After any modifications, build a new Cilium container image and distribute it.
