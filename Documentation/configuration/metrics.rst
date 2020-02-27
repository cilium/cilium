.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _metrics:

********************
Monitoring & Metrics
********************

``cilium-agent`` and ``cilium-operator`` can be configured to serve `Prometheus
<https://prometheus.io>`_ metrics. Prometheus is a pluggable metrics collection
and storage system and can act as a data source for `Grafana
<https://grafana.com/>`_, a metrics visualization frontend. Unlike some metrics
collectors like statsd, Prometheus requires the collectors to pull metrics from
each source.

To run Cilium with Prometheus metrics enabled, deploy it with the
``global.prometheus.enabled=true`` Helm value set.

All metrics are exported under the ``cilium`` Prometheus namespace. When
running and collecting in Kubernetes they will be tagged with a pod name and
namespace.

Installation
============

When deployed with the Helm value ``global.prometheus.enabled=true``, all Cilium
components will have the annotations to signal Prometheus whether to scrape
metrics:

.. code-block:: yaml

        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"

Example Prometheus & Grafana Deployment
---------------------------------------

If you don't have an existing Prometheus and Grafana stack running, you can
deploy a stack with:

.. parsed-literal::

    kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/addons/prometheus/monitoring-example.yaml

It will run Prometheus and Grafana in the ``cilium-monitoring`` namespace. You
can then expose Grafana to access it via your browser.

.. code:: bash

    kubectl -n cilium-monitoring port-forward service/grafana 3000:3000

Open your browser and access ``https://localhost:3000/``

cilium-agent
============

To expose any metrics, invoke ``cilium-agent`` with the
``--prometheus-serve-addr`` option. This option takes a ``IP:Port`` pair but
passing an empty IP (e.g. ``:9090``) will bind the server to all available
interfaces (there is usually only one in a container).

in :git-tree:`examples/kubernetes/addons/prometheus/monitoring-example.yaml`

Exported Metrics
----------------

Endpoint
~~~~~~~~

============================================ ================================================== ========================================================
Name                                         Labels                                             Description
============================================ ================================================== ========================================================
``endpoint_count``                                                                              Number of endpoints managed by this agent
``endpoint_regenerations``                   ``outcome``                                        Count of all endpoint regenerations that have completed
``endpoint_regeneration_time_stats_seconds`` ``scope``                                          Endpoint regeneration time stats
``endpoint_state``                           ``state``                                          Count of all endpoints
============================================ ================================================== ========================================================

Services
~~~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``services_events_total``                                                                     Number of services events labeled by action type
========================================== ================================================== ========================================================

Datapath
~~~~~~~~

============================================= ================================================== ========================================================
Name                                          Labels                                             Description
============================================= ================================================== ========================================================
``datapath_errors_total``                     ``area``, ``name``, ``family``                     Total number of errors occurred in datapath management
``datapath_conntrack_gc_runs_total``          ``status``                                         Number of times that the conntrack garbage collector process was run
``datapath_conntrack_gc_key_fallbacks_total``                                                    The number of alive and deleted conntrack entries at the end of a garbage collector run labeled by datapath family
``datapath_conntrack_gc_entries``             ``family``                                         The number of alive and deleted conntrack entries at the end of a garbage collector run
``datapath_conntrack_gc_duration_seconds``    ``status``                                         Duration in seconds of the garbage collector process
============================================= ================================================== ========================================================

BPF
~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``bpf_syscall_duration_seconds``           ``operation``, ``outcome``                         Duration of BPF system call performed
``bpf_map_ops_total``                      ``mapName``, ``operation``, ``outcome``            Number of BPF map operations performed
========================================== ================================================== ========================================================

Drops/Forwards (L3/L4)
~~~~~~~~~~~~~~~~~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``drop_count_total``                       ``reason``, ``direction``                          Total dropped packets
``drop_bytes_total``                       ``reason``, ``direction``                          Total dropped bytes
``forward_count_total``                    ``direction``                                      Total forwarded packets
``forward_bytes_total``                    ``direction``                                      Total forwarded bytes
========================================== ================================================== ========================================================

Policy
~~~~~~

========================================== ================================================== ========================================================
Name                                       Labels                                             Description
========================================== ================================================== ========================================================
``policy_count``                                                                              Number of policies currently loaded
``policy_regeneration_total``                                                                 Total number of policies regenerated successfully
``policy_regeneration_time_stats_seconds`` ``scope``                                          Policy regeneration time stats labeled by the scope
``policy_max_revision``                                                                       Highest policy revision number in the agent
``policy_import_errors``                                                                      Number of times a policy import has failed
``policy_endpoint_enforcement_status``                                                        Number of endpoints labeled by policy enforcement status
========================================== ================================================== ========================================================

Policy L7 (HTTP/Kafka)
~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``proxy_redirects``                      ``protocol``                                       Number of redirects installed for endpoints
``proxy_upstream_reply_seconds``                                                            Seconds waited for upstream server to reply to a request
``policy_l7_total``                      ``type``                                           Number of total L7 requests/responses
======================================== ================================================== ========================================================

Identity
~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``identity_count``                                                                          Number of identities currently allocated
======================================== ================================================== ========================================================

Events external to Cilium
~~~~~~~~~~~~~~~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``event_ts``                             ``source``                                         Last timestamp when we received an event
======================================== ================================================== ========================================================

Controllers
~~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``controllers_runs_total``               ``status``                                         Number of times that a controller process was run
``controllers_runs_duration_seconds``    ``status``                                         Duration in seconds of the controller process
======================================== ================================================== ========================================================

SubProcess
~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``subprocess_start_total``               ``subsystem``                                      Number of times that Cilium has started a subprocess
======================================== ================================================== ========================================================

Kubernetes
~~~~~~~~~~

======================================== ================================================== ========================================================
Name                                     Labels                                             Description
======================================== ================================================== ========================================================
``kubernetes_events_received_total``     ``scope``, ``action``, ``validity``, ``equiality`` Number of Kubernetes events received
``kubernetes_events_total``              ``scope``, ``action``, ``outcome``                 Number of Kubernetes events processed
``k8s_cnp_status_completion_seconds``    ``attempts``, ``outcome``                          Duration in seconds in how long it took to complete a CNP status update
======================================== ================================================== ========================================================

IPAM
~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``ipam_events_total``                                                                 Number of IPAM events received labeled by action and datapath family type
======================================== ============================================ ========================================================

KVstore
~~~~~~~

======================================== ============================================ ========================================================
Name                                     Labels                                       Description
======================================== ============================================ ========================================================
``kvstore_operations_duration_seconds``  ``action``, ``kind``, ``outcome``, ``scope`` Duration of kvstore operation
``kvstore_events_queue_seconds``         ``action``, ``scope``                        Duration of seconds of time received event was blocked before it could be queued
======================================== ============================================ ========================================================

Agent
~~~~~

================================ ================================ ========================================================
Name                             Labels                           Description
================================ ================================ ========================================================
``agent_bootstrap_seconds``      ``scope``, ``outcome``           Duration of various bootstrap phases
``api_process_time_seconds``                                      Processing time of all the API calls made to the cilium-agent, labeled by API method, API path and returned HTTP code.
================================ ================================ ========================================================

FQDN
~~~~

================================ ================================ ========================================================
Name                             Labels                           Description
================================ ================================ ========================================================
``qdn_gc_deletions_total``                                        Number of FQDNs that have been cleaned on FQDN garbage collector job
================================ ================================ ========================================================

cilium-operator
===============

``cilium-operator`` can be configured to serve metrics by running with the
option ``--enable-metrics``.  By default, the operator will expose metrics on
port 6942, the port can be changed with the option ``--metrics-address``.

Exported Metrics
----------------

All metrics are exported under the ``cilium_operator_`` Prometheus namespace.

.. _ipam_metrics:

IPAM
~~~~

======================================== ================================ ========================================================
Name                                     Labels                           Description
======================================== ================================ ========================================================
``ipam_ips``                             ``type``                         Number of IPs allocated
``ipam_allocation_ops``                  ``subnetId``                     Number of IP allocation operations
``ipam_interface_creation_ops``          ``subnetId``, ``status``         Number of interfaces creation operations
``ipam_available``                                                        Number of interfaces with addresses available
``ipam_nodes_at_capacity``                                                Number of nodes unable to allocate more addresses
``ipam_resync_total``                                                     Number of synchronization operations with external IPAM API
``ipam_api_duration_seconds``            ``operation``, ``responseCode``  Duration of interactions with external IPAM API
``ipam_api_rate_limit_duration_seconds`` ``operation``                    Duration of rate limiting while accessing external IPAM API
======================================== ================================ ========================================================
