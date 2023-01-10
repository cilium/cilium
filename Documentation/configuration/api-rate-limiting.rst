.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _api_rate_limiting:

*****************
API Rate Limiting
*****************

The per node Cilium agent is essentially event-driven. For example, the CNI
plugin is invoked when a new workload is scheduled onto the node which in turn
makes an API call to the Cilium agent to allocate an IP address and create the
Cilium endpoint. Another example is loading of network policy or service
definitions where changes of these definitions will create an event which will
notify the Cilium agent that a modification is required.

Due to being event-driven, the amount of work performed by the Cilium agent
highly depends on the rate of external events it receives. In order to
constrain the resources that the Cilium agent consumes, it can be helpful to
restrict the rate and allowed parallel executions of API calls.

Default Rate Limits
===================

The following API calls are currently subject to rate limiting:

========================== ====== ===== ============= ============ ================= =========== ===============================
API Call                   Limit  Burst Max Parallel  Min Parallel Max Wait Duration Auto Adjust Estimated Processing Duration
========================== ====== ===== ============= ============ ================= =========== ===============================
``PUT /endpoint/{id}``     0.5/s  4     4                          15s               True        2s
``DELETE /endpoint/{id}``               4             4                              True        200ms
``GET /endpoint/{id}/*``   4/s    4     4             2            10s               True        200ms
``PATCH /endpoint/{id}*``  0.5/s  4     4                          15s               True        1s
``GET /endpoint``          1/s    4     2             2                              True        300ms
========================== ====== ===== ============= ============ ================= =========== ===============================

Configuration
=============

The ``api-rate-limit`` option can be used to overwrite individual settings of the
default configuration::

   --api-rate-limit endpoint-create=rate-limit:2/s,rate-burst:4

API call to Configuration mapping
---------------------------------

========================== ====================
API Call                   Config Name
========================== ====================
``PUT /endpoint/{id}``     ``endpoint-create``
``DELETE /endpoint/{id}``  ``endpoint-delete``
``GET /endpoint/{id}/*``   ``endpoint-get``
``PATCH /endpoint/{id}*``  ``endponit-patch``
``GET /endpoint``          ``endpoint-list``
========================== ====================

Configuration Parameters
------------------------

================================= ========= ========= =====================================================================================
Configuration Key                 Example   Default   Description
================================= ========= ========= =====================================================================================
``rate-limit``                    ``5/m``   None      Allowed requests per time unit in the format ``<number>/<duration>``.
``rate-burst``                    ``4``     None      Burst of API requests allowed by rate limiter.
``min-wait-duration``             ``10ms``  ``0``     Minimum wait duration each API call has to wait before being processed.
``max-wait-duration``             ``15s``   ``0``     Maximum duration an API call is allowed to wait before it fails.
``estimated-processing-duration`` ``100ms`` ``0``     Estimated processing duration of an average API call. Used for automatic adjustment.
``auto-adjust``                   ``true``  ``false`` Enable automatic adjustment of ``rate-limit``, ``rate-burst`` and ``parallel-requests``.
``parallel-requests``             ``4``     ``0``     Number of parallel API calls allowed.
``min-parallel-requests``         ``2``     ``0``     Lower limit of parallel requests when auto-adjusting.
``max-parallel-requests``         ``6``     ``0``     Upper limit of parallel requests when auto-adjusting.
``mean-over``                     ``10``    ``10``    Number of API calls to calculate mean processing duration for auto adjustment.
``log``                           ``true``  ``false`` Log an Info message for each API call processed.
``delayed-adjustment-factor``     ``0.25``  ``0.5``   Factor for slower adjustment of ``rate-burst`` and ``parallel-requests``.
``max-adjustment-factor``         ``10.0``  ``100.0`` Maximum factor the auto-adjusted values can deviate from the initial base values configured.
================================= ========= ========= =====================================================================================

Valid duration values
---------------------

The ``rate-limit`` option expects a value in the form ``<number>/<duration>``
where ``<duration>`` is a value that can be parsed with `ParseDuration()
<https://golang.org/pkg/time/#ParseDuration>`_. The supported units are:
``ns``, ``us``, ``ms``, ``s``, ``m``, ``h``.

**Examples:**

* ``rate-limit:10/2m``
* ``rate-limit:3.5/h``
* ``rate-limit:1/100ms``

Automatic Adjustment
====================

Static values are relatively useless as the Cilium agent will run on different
machine types. Deriving rate limits based on number of available CPU cores or
available memory can be misleading as well as the Cilium agent may be subject
to CPU and memory constraints.

For this reason, all API call rate limiting is done with automatic adjustment
of the limits with the goal to stay as close as possible to the configured
estimated processing duration. This processing duration is specified for each
group of API call and is constantly monitored.

On completion of every API call, new limits are calculated. For this purpose, an
adjustment factor is calculated:

.. code-block:: go

    AdjustmentFactor := EstimatedProcessingDuration / MeanProcessingDuration
    AdjustmentFactor = Min(Max(AdjustmentFactor, 1.0/MaxAdjustmentFactor), MaxAdjustmentFactor)

This adjustment factor is then applied to ``rate-limit``, ``rate-burst`` and
``parallel-requests`` and will steer the mean processing duration to get closer
to the estimated processing duration.

If ``delayed-adjustment-factor`` is specified, then this additional factor is
used to slow the growth of the ``rate-burst`` and ``parallel-requests`` as both
values should typically adjust slower than ``rate-limit``:

.. code-block:: go

    NewValue = OldValue * AdjustmentFactor
    NewValue = OldValue + ((NewValue - OldValue) * DelayedAdjustmentFactor)

Metrics
=======

All API calls subject to rate limiting will expose :ref:`metrics_api_rate_limiting`. Example::

    cilium_api_limiter_adjustment_factor                  api_call="endpoint-create"                               0.695787
    cilium_api_limiter_processed_requests_total           api_call="endpoint-create" outcome="success"             7.000000
    cilium_api_limiter_processing_duration_seconds        api_call="endpoint-create" value="estimated"             2.000000
    cilium_api_limiter_processing_duration_seconds        api_call="endpoint-create" value="mean"                  2.874443
    cilium_api_limiter_rate_limit                         api_call="endpoint-create" value="burst"                 4.000000
    cilium_api_limiter_rate_limit                         api_call="endpoint-create" value="limit"                 0.347894
    cilium_api_limiter_requests_in_flight                 api_call="endpoint-create" value="in-flight"             0.000000
    cilium_api_limiter_requests_in_flight                 api_call="endpoint-create" value="limit"                 0.000000
    cilium_api_limiter_wait_duration_seconds              api_call="endpoint-create" value="max"                  15.000000
    cilium_api_limiter_wait_duration_seconds              api_call="endpoint-create" value="mean"                  0.000000
    cilium_api_limiter_wait_duration_seconds              api_call="endpoint-create" value="min"                   0.000000

Understanding the log output
============================

The API rate limiter logs under the ``rate`` subsystem. An example message can
be seen below::

   level=info msg="API call has been processed" name=endpoint-create processingDuration=772.847247ms subsys=rate totalDuration=14.923958916s uuid=d34a2e1f-1ac9-11eb-8663-42010a8a0fe1 waitDurationTotal=14.151023084s

The following is an explanation for all the API rate limiting messages:

::

   "Processing API request with rate limiter"

The request was admitted into the rate limiter. The associated HTTP context
(caller's request) has not yet timed out. The request will now be rate-limited
according to the configuration of the rate limiter. It will enter the waiting
stage according to the computed waiting duration.

::

   "API request released by rate limiter"


The request has finished waiting its computed duration to achieve
rate-limiting. The underlying HTTP API action will now take place. This means
that this request was not thrown back at the caller with a 429 HTTP status
code.

This is a common message when the requests are being processed within the
configured bounds of the rate limiter.

::

   "API call has been processed":

The API rate limiter has processed this request and the underlying HTTP API
action has finished. This means the request is no longer actively waiting or in
other words, no longer being rate-limited. This does not mean the underlying
HTTP action has succeeded; only that this request has been dealt with.

::

   "Not processing API request due to cancelled context"

The underlying HTTP context (request) was cancelled. In other words, the caller
has given up on the request. This most likely means that the HTTP request timed
out. A 429 HTTP response status code is returned to the caller, which may or
may not receive it anyway.

::

   "Not processing API request. Wait duration for maximum parallel requests exceeds maximum"

The request has been denied by the rate limiter because too many parallel
requests are already in flight. The caller will receive a 429 HTTP status
response.

This is a common message when the rate limiter is doing its job of preventing
too many parallel requests at once.

::

   "Not processing API request. Wait duration exceeds maximum"

The request has been denied by the rate limiter because the request's waiting
duration would exceed the maximum configured waiting duration. For example, if
the maximum waiting duration was ``5s`` and due to the backlog of the rate
limiter, this request would need to wait ``10s``, then this request would be
thrown out. A 429 HTTP response status code would be returned to the caller.

This is the most common message when the rate limiter is doing its job of
pacing the incoming requests into Cilium.

::

   "Not processing API request due to cancelled context while waiting"

The request has been denied by the rate limiter because after the request has
waited its calculated waiting duration, the context associated with the request
has been cancelled. In the most likely scenario, this means that there was an
HTTP timeout while the request was actively being rate-limited or in other
words, actively being delayed by the rate limiter. A 429 HTTP response status
code is returned to the caller.
