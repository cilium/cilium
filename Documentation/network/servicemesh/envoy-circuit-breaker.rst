.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_envoy_circuit_breaker:

*******************
L7 Circuit Breaking
*******************

Cilium Service Mesh defines a ``CiliumClusterwideEnvoyConfig`` CRD which allows users
to set the configuration of the Envoy component built into Cilium agents.

Circuit breaking is an important pattern for creating resilient microservice applications. 
Circuit breaking allows you to write applications that limit the impact of failures, latency spikes, 
and other undesirable effects of network peculiarities.

You will configure Circuit breaking rules with ``CiliumClusterwideEnvoyConfig`` and then test the configuration 
by intentionally “tripping” the circuit breaker in this example.

Deploy Test Applications
========================

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/test-application-proxy-circuit-breaker.yaml

The test workloads consist of:

- One client Deployment, ``fortio-deploy``
- One Service, ``echo-service``

View information about these Pods:

.. code-block:: shell-session

    $ kubectl get pods --show-labels -o wide
    NAME                             READY   STATUS    RESTARTS   AGE     IP           NODE                       NOMINATED NODE   READINESS GATES   LABELS
    echo-service-59557f5857-xh84s    2/2     Running   0          7m37s   10.0.0.125   cilium-control-plane   <none>           <none>            kind=echo,name=echo-service,other=echo,pod-template-hash=59557f5857
    fortio-deploy-687945c6dc-6qnh4   1/1     Running   0          7m37s   10.0.0.109   cilium-control-plane   <none>           <none>            app=fortio,pod-template-hash=687945c6dc


Configuring Envoy Circuit Breaker
=================================

Apply the ``envoy-circuit-breaker.yaml`` file, which defines a ``CiliumClusterwideEnvoyConfig``.


.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-circuit-breaker.yaml

.. include:: warning.rst

Verify the ``CiliumClusterwideEnvoyConfig`` was created correctly.

.. code-block:: shell-session

    $ kubectl get ccec envoy-circuit-breaker -oyaml
    apiVersion: cilium.io/v2
    kind: CiliumClusterwideEnvoyConfig
    ...
    resources:
    - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
      name: "default/echo-service"
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      type: EDS
      circuit_breakers:
        thresholds:
        - priority: "DEFAULT"
          max_requests: 2
          max_pending_requests: 1
      outlier_detection:
        split_external_local_origin_errors: true
        consecutive_local_origin_failure: 2
    services:
    - name: echo-service
      namespace: default

In the ``CiliumClusterwideEnvoyConfig`` settings, you specified ``max_pending_requests: 1`` and ``max_requests: 2``. 
These rules indicate that if you exceed more than one connection and request concurrently,
you will see some failures when the envoy opens the circuit for further requests and connections.

Tripping Envoy Circuit Breaker
==============================

Make an environment variable with the Pod name for fortio:

.. code-block:: shell-session

    $ export FORTIO_POD=$(kubectl get pods -l app=fortio -o 'jsonpath={.items[0].metadata.name}')

Use the following command to call the Service with two concurrent connections using the ``-c 2`` flag and send 20 requests using ``-n 20`` flag:

.. code-block:: shell-session

    $ kubectl exec "$FORTIO_POD" -c fortio -- /usr/bin/fortio load -c 2 -qps 0 -n 20 http://echo-service:8080

Output::

    $ kubectl exec "$FORTIO_POD" -c fortio -- /usr/bin/fortio load -c 2 -qps 0 -n 20 http://echo-service:8080
    {"ts":1692767216.838976,"level":"info","file":"scli.go","line":107,"msg":"Starting Φορτίο 1.57.3 h1:kdPlBiws3cFsLcssZxCt2opFmHj14C3yPBokFhMWzmg= go1.20.6 amd64 linux"}
    Fortio 1.57.3 running at 0 queries per second, 4->4 procs, for 20 calls: http://echo-service:8080
    {"ts":1692767216.839520,"level":"info","file":"httprunner.go","line":100,"msg":"Starting http test","run":"0","url":"http://echo-service:8080","threads":"2","qps":"-1.0","warmup":"parallel","conn-reuse":""}
    Starting at max qps with 2 thread(s) [gomax 4] for exactly 20 calls (10 per thread + 0)
    {"ts":1692767216.842149,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"1","run":"0"}
    {"ts":1692767216.854289,"level":"info","file":"periodic.go","line":832,"msg":"T001 ended after 13.462339ms : 10 calls. qps=742.8129688310479"}
    {"ts":1692767216.854985,"level":"info","file":"periodic.go","line":832,"msg":"T000 ended after 14.158587ms : 10 calls. qps=706.2851681456631"}
    Ended after 14.197088ms : 20 calls. qps=1408.7
    {"ts":1692767216.855035,"level":"info","file":"periodic.go","line":564,"msg":"Run ended","run":"0","elapsed":"14.197088ms","calls":"20","qps":"1408.739595049351"}
    Aggregated Function Time : count 20 avg 0.0013703978 +/- 0.000461 min 0.00092124 max 0.002696039 sum 0.027407957
    # range, mid point, percentile, count
    >= 0.00092124 <= 0.001 , 0.00096062 , 10.00, 2
    > 0.001 <= 0.002 , 0.0015 , 90.00, 16
    > 0.002 <= 0.00269604 , 0.00234802 , 100.00, 2
    # target 50% 0.0015
    # target 75% 0.0018125
    # target 90% 0.002
    # target 99% 0.00262644
    # target 99.9% 0.00268908
    Error cases : count 1 avg 0.00133143 +/- 0 min 0.00133143 max 0.00133143 sum 0.00133143
    # range, mid point, percentile, count
    >= 0.00133143 <= 0.00133143 , 0.00133143 , 100.00, 1
    # target 50% 0.00133143
    # target 75% 0.00133143
    # target 90% 0.00133143
    # target 99% 0.00133143
    # target 99.9% 0.00133143
    # Socket and IP used for each connection:
    [0]   1 socket used, resolved to 10.96.182.43:8080, connection timing : count 1 avg 0.000426815 +/- 0 min 0.000426815 max 0.000426815 sum 0.000426815
    [1]   2 socket used, resolved to 10.96.182.43:8080, connection timing : count 2 avg 0.0004071275 +/- 0.0001215 min 0.000285596 max 0.000528659 sum 0.000814255
    Connection time histogram (s) : count 3 avg 0.00041369 +/- 9.966e-05 min 0.000285596 max 0.000528659 sum 0.00124107
    # range, mid point, percentile, count
    >= 0.000285596 <= 0.000528659 , 0.000407128 , 100.00, 3
    # target 50% 0.000346362
    # target 75% 0.00043751
    # target 90% 0.0004922
    # target 99% 0.000525013
    # target 99.9% 0.000528294
    Sockets used: 3 (for perfect keepalive, would be 2)
    Uniform: false, Jitter: false, Catchup allowed: true
    IP addresses distribution:
    10.96.182.43:8080: 3
    Code 200 : 19 (95.0 %)
    Code 503 : 1 (5.0 %)
    Response Header Sizes : count 20 avg 370.5 +/- 85 min 0 max 390 sum 7410
    Response Body/Total Sizes : count 20 avg 2340.15 +/- 465.7 min 310 max 2447 sum 46803
    All done 20 calls (plus 0 warmup) 1.370 ms avg, 1408.7 qps

From the above output, you can see that the response code of some requests is 503, 
which triggers a circuit breaker.

Bring the number of concurrent connections up to 4.

Output::

    $ kubectl exec "$FORTIO_POD" -c fortio -- /usr/bin/fortio load -c 4 -qps 0 -n 20 http://echo-service:8080
    {"ts":1692767495.818546,"level":"info","file":"scli.go","line":107,"msg":"Starting Φορτίο 1.57.3 h1:kdPlBiws3cFsLcssZxCt2opFmHj14C3yPBokFhMWzmg= go1.20.6 amd64 linux"}
    Fortio 1.57.3 running at 0 queries per second, 4->4 procs, for 20 calls: http://echo-service:8080
    {"ts":1692767495.819105,"level":"info","file":"httprunner.go","line":100,"msg":"Starting http test","run":"0","url":"http://echo-service:8080","threads":"4","qps":"-1.0","warmup":"parallel","conn-reuse":""}
    Starting at max qps with 4 thread(s) [gomax 4] for exactly 20 calls (5 per thread + 0)
    {"ts":1692767495.822424,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"3","run":"0"}
    {"ts":1692767495.822428,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"0","run":"0"}
    {"ts":1692767495.822603,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"1","run":"0"}
    {"ts":1692767495.823855,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"0","run":"0"}
    {"ts":1692767495.825250,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"1","run":"0"}
    {"ts":1692767495.825285,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"0","run":"0"}
    {"ts":1692767495.827282,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"0","run":"0"}
    {"ts":1692767495.827514,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"2","run":"0"}
    {"ts":1692767495.829886,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"0","run":"0"}
    {"ts":1692767495.830156,"level":"info","file":"periodic.go","line":832,"msg":"T000 ended after 9.136284ms : 5 calls. qps=547.268451812575"}
    {"ts":1692767495.830326,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"2","run":"0"}
    {"ts":1692767495.831175,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"3","run":"0"}
    {"ts":1692767495.832826,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"3","run":"0"}
    {"ts":1692767495.834028,"level":"warn","file":"http_client.go","line":1104,"msg":"Non ok http code","code":"503","status":"HTTP/1.1 503","thread":"3","run":"0"}
    {"ts":1692767495.834116,"level":"info","file":"periodic.go","line":832,"msg":"T003 ended after 13.09904ms : 5 calls. qps=381.7073617608619"}
    {"ts":1692767495.834865,"level":"info","file":"periodic.go","line":832,"msg":"T001 ended after 13.846811ms : 5 calls. qps=361.09397318992796"}
    {"ts":1692767495.835370,"level":"info","file":"periodic.go","line":832,"msg":"T002 ended after 14.352324ms : 5 calls. qps=348.3756358900482"}
    Ended after 14.386516ms : 20 calls. qps=1390.2
    {"ts":1692767495.835489,"level":"info","file":"periodic.go","line":564,"msg":"Run ended","run":"0","elapsed":"14.386516ms","calls":"20","qps":"1390.1906479650806"}
    Aggregated Function Time : count 20 avg 0.0024801033 +/- 0.001782 min 0.000721482 max 0.008055527 sum 0.049602066
    # range, mid point, percentile, count
    >= 0.000721482 <= 0.001 , 0.000860741 , 10.00, 2
    > 0.001 <= 0.002 , 0.0015 , 45.00, 7
    > 0.002 <= 0.003 , 0.0025 , 80.00, 7
    > 0.003 <= 0.004 , 0.0035 , 85.00, 1
    > 0.005 <= 0.006 , 0.0055 , 95.00, 2
    > 0.008 <= 0.00805553 , 0.00802776 , 100.00, 1
    # target 50% 0.00214286
    # target 75% 0.00285714
    # target 90% 0.0055
    # target 99% 0.00804442
    # target 99.9% 0.00805442
    Error cases : count 13 avg 0.0016602806 +/- 0.0006006 min 0.000721482 max 0.00281812 sum 0.021583648
    # range, mid point, percentile, count
    >= 0.000721482 <= 0.001 , 0.000860741 , 15.38, 2
    > 0.001 <= 0.002 , 0.0015 , 61.54, 6
    > 0.002 <= 0.00281812 , 0.00240906 , 100.00, 5
    # target 50% 0.00175
    # target 75% 0.00228634
    # target 90% 0.00260541
    # target 99% 0.00279685
    # target 99.9% 0.00281599
    # Socket and IP used for each connection:
    [0]   5 socket used, resolved to 10.96.182.43:8080, connection timing : count 5 avg 0.0003044688 +/- 0.0001472 min 0.000120654 max 0.00053878 sum 0.001522344
    [1]   3 socket used, resolved to 10.96.182.43:8080, connection timing : count 3 avg 0.00041437933 +/- 9.571e-05 min 0.000330279 max 0.000548277 sum 0.001243138
    [2]   3 socket used, resolved to 10.96.182.43:8080, connection timing : count 3 avg 0.00041114067 +/- 0.0001352 min 0.000306734 max 0.00060203 sum 0.001233422
    [3]   4 socket used, resolved to 10.96.182.43:8080, connection timing : count 4 avg 0.00038631225 +/- 0.0002447 min 0.000175125 max 0.00080311 sum 0.001545249
    Connection time histogram (s) : count 15 avg 0.0003696102 +/- 0.0001758 min 0.000120654 max 0.00080311 sum 0.005544153
    # range, mid point, percentile, count
    >= 0.000120654 <= 0.00080311 , 0.000461882 , 100.00, 15
    # target 50% 0.000437509
    # target 75% 0.000620309
    # target 90% 0.00072999
    # target 99% 0.000795798
    # target 99.9% 0.000802379
    Sockets used: 15 (for perfect keepalive, would be 4)
    Uniform: false, Jitter: false, Catchup allowed: true
    IP addresses distribution:
    10.96.182.43:8080: 15
    Code 200 : 7 (35.0 %)
    Code 503 : 13 (65.0 %)
    Response Header Sizes : count 20 avg 136.5 +/- 186 min 0 max 390 sum 2730
    Response Body/Total Sizes : count 20 avg 1026.9 +/- 1042 min 241 max 2447 sum 20538
    All done 20 calls (plus 0 warmup) 2.480 ms avg, 1390.2 qps

Now you can start to see the expected Circuit breaking behavior. 
Only 35% of the requests succeeded and the rest were trapped by Circuit breaking.

.. parsed-literal::
    Code 200 : 7 (35.0 %)
    Code 503 : 13 (65.0 %)


Cleaning up
===========

Remove the rules.

.. parsed-literal::

    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-circuit-breaker.yaml

Remove the test application.

.. parsed-literal::

    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/test-application-proxy-circuit-breaker.yaml
