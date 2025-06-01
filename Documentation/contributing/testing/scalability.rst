.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _scalability_testing:

Scalability and Performance Testing
===================================

Introduction
~~~~~~~~~~~~

Cilium scalability and performance tests leverage `ClusterLoader2 <CL2_>`_.
For an overview of ClusterLoader2, please refer to the `Readme <CL2_README_>`_ and `Getting Started <CL2_GETTING_STARTED_>`_.
At a high level, ClusterLoader2 allows for specifying states of the cluster, how to transition between them
and what metrics to measure during the test run.
Additionally, it allows for failing the test if the metrics are not within the expected thresholds.

Overview of existing tests
~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests based on kOps and GCP VMs:

* 100 nodes scale test - ``/scale-100`` `Workflow <SCALE_100_WORKFLOW_>`_ that executes two test scenarios:

    * `Upstream load test <UPSTREAM_LOAD_TEST_>`_

    * `Network policy scale test <NETPOL_SCALE_TEST_>`_


* FQDN performance test - ``/fqdn-perf`` `Workflow <FQDN_PERF_WORKFLOW_>`_
  is a simple two-node test that deploys pods with FQDN policies
  and measures the time it takes to resolve FQDNs from a client point of view.

* ClusterMesh scale test - ``/scale-clustermesh`` `Workflow <CLUSTERMESH_WORKFLOW_>`_ leverages
  a `mock Clustermesh control plane <CLUSTERMESH_MOCK_>`_ that simulates large deployments of ClusterMesh.

Test based on EKS:

* Egress Gateway scale test - ``/scale-egw``. `Workflow <EGW_WORKFLOW_>`_ tests Egress Gateway on a small cluster,
  but with synthetically created Endpoints and Nodes to simulate a large cluster.

Whenever developing a new test, consider if you want to add a test to an already existing workflow,
create a new one, or extend some existing test.
If you are unsure, you can always ask in the ``#sig-scalabilty`` `Slack channel <SLACK_CHANNEL_>`_.
For example, if you want to run a test on a large cluster,
you might consider adding it as a separate test scenario to the already existing 100-nodes scale test
to reduce the cost of CI, because spinning up a new cluster and tearing it down is quite a long process.
For some use cases, it might be better to simulate only a large cluster but execute the test on a small cluster,
like in the case of the Egress Gateway scale test or the ClusterMesh scale test.

Running CL2 tests locally
~~~~~~~~~~~~~~~~~~~~~~~~~

Each CL2 test should be designed in a way that scales with the number of nodes.
This allows for running a specific test case scenario in a local environment, to validate the test case.
For example, let's run the network policy scale test in a local Kind cluster.
First, set up a Kind cluster with Cilium, as documented in :ref:`dev_env`.
Build the ClusterLoader2 binary from the `perf-tests repository <CL2_>`_.
Then you can run:

.. code-block:: bash

    export CL2_PROMETHEUS_PVC_ENABLED=false
    export CL2_PROMETHEUS_SCRAPE_CILIUM_OPERATOR=true
    export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT=true
    export CL2_PROMETHEUS_SCRAPE_CILIUM_AGENT_INTERVAL=5s

    ./clusterloader \
    -v=2 \
    --testconfig=.github/actions/cl2-modules/netpol/config.yaml \
    --provider=kind \
    --enable-prometheus-server \
    --nodes=1 \
    --report-dir=./report \
    --prometheus-scrape-kube-proxy=false \
    --prometheus-apiserver-scrape-port=6443 \
    --kubeconfig=$HOME/.kube/config


Some additional options worth mentioning are:

* ``--tear-down-prometheus-server=false`` - Leaves Prometheus and Grafana running after the test finishes, this helps speed up the test run
  when running multiple tests in a row, but also for exploring the metrics in Grafana.
* ``--experimental-prometheus-snapshot-to-report-dir=true`` - Creates a snapshot of the Prometheus data and saves it to the report directory

By setting ``deleteAutomanagedNamespaces: false`` in the test config, you can also leave
the test namespaces after the test finishes. This is especially useful for checking if your test
created the expected resources.

At the end of output, the test should end successfully with::

    clusterloader.go:252] --------------------------------------------------------------------------------
    clusterloader.go:253] Test Finished
    clusterloader.go:254]   Test: .github/actions/cl2-modules/netpol/config.yaml
    clusterloader.go:255]   Status: Success
    clusterloader.go:259] --------------------------------------------------------------------------------


All the test results are saved in the report directory, ``./report`` in this case.
Most importantly, it contains:

* ``generatedConfig_netpol.yaml`` - Rendered test scenario
* ``'GenericPrometheusQuery NetPol Average CPU Usage_netpol_.*.json'`` - ``GenericPrometheusQuery`` 
  contains results of the Prometheus queries executed during the test.
  In this example, it contains the CPU usage of the Cilium agents. 
  All of the Prometheus Queries will be automatically visualized in :ref:`perfdash <perfdashdocs>`.
* ``'PodPeriodicCommand.*Profiles-stdout.*'`` - Contains memory and CPU profiles gathered during the test run. 
  To understand how to interpret them, refer to the :ref:`profiling` subsection.


Accessing Grafana and Prometheus during the test run
""""""""""""""""""""""""""""""""""""""""""""""""""""

During the test execution, ClusterLoader2 deploys Prometheus and Grafana to the cluster.
You can access Grafana and Prometheus by running:

.. code-block:: bash

    kubectl port-forward -n monitoring svc/grafana 3000
    kubectl port-forward -n monitoring svc/prometheus-k8s 9090

This can be especially useful for exploring the metrics and adding additional queries to the test.

Metrics-based testing and alerting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes, you might want to scrape additional targets during test execution on top of the default ones.
In this case, you can simply create a Pod or Service monitor `example monitor <EXAMPLE_MONITOR_>`_.
Then you need to pass it as an additional argument to ClusterLoader2:

.. code-block:: bash

    ./clusterloader \
    --prometheus-additional-monitors-path=../../.github/actions/cl2-modules/egw/prom-extra-podmons
    ...

Now you can use the additional metrics in your test, by leveraging regular ``GenericPrometheusQuery`` measurement.
For example, Egress Gateway ensures that various percentiles of masquerade latency observed by clients are
`below specific thresholds <EGW_MASQ_METRICS_>`_. This can be achieved by the following measurement in ClusterLoader2:

.. code-block:: yaml

  - Identifier: MasqueradeDelay{{ .metricsSuffix }}
    Method: GenericPrometheusQuery
    Params:
      action: {{ .action }}
      metricName: Masquerade Delay {{ .metricsSuffix }}
      metricVersion: v1
      unit: s
      enableViolations: true
      queries:
      - name: P95
        query: quantile(0.95, egw_scale_test_masquerade_delay_seconds_total{k8s_instance="{{ .instance }}"})
        threshold: {{ $MASQ_DELAY_THRESHOLD }}


Running tests in CI
~~~~~~~~~~~~~~~~~~~

Once you are happy with the test and validated it locally, you can create a PR with the test.
You can base your GitHub workflow on the existing tests, or add a test scenario to an already existing workflow.


Accessing test results from PR or CI runs
"""""""""""""""""""""""""""""""""""""""""

You can run the specific scalability or performance test in your PR, some example commands are::

    /scale-100
    /scale-clustermesh
    /scale-egw
    /fqdn-perf

After the test run, all results will be saved in the Google Storage bucket.
In the workflow run, you will see a link to the test results at the bottom.
For example, open `test runs <TEST_RUN_>`_ and pick one of the runs.
You should see a link like this:

::

    EXPORT_DIR: gs://cilium-scale-results/logs/scale-100-main/1745287079

To see how to install gsutil check `Install gsutil <GSUTIL_INSTALL>`_ section.
To see the results, you can run:

.. code-block:: bash

    gsutil ls -r gs://cilium-scale-results/logs/scale-100-main/1745287079

You can also copy results to your local machine by running:

.. code-block:: bash

    gsutil -m cp -r gs://cilium-scale-results/logs/scale-100-main/1745287079 .


.. _perfdashdocs:

Visualizing results in Perfdash
"""""""""""""""""""""""""""""""

Perfdash leverages exported results from ClusterLoader2 and visualizes them.
Currently, we do not host a publicly available instance of Perfdash.
To visualize the results, please check the `Scaffolding repository <PERFDASH_>`_.
As an example, you can check CPU usage of the Cilium agent:

.. image:: /images/perfdash.png
    :align: center

Note that clicking on the graph redirects you to the Google Cloud Storage page containing all of the results
for the specific test run.

Accessing Prometheus snapshot
"""""""""""""""""""""""""""""

Each test run creates a snapshot of the Prometheus data and saves it to the report directory.
This is enabled by setting ``--experimental-prometheus-snapshot-to-report-dir=true``.
Prometheus snapshots help with debugging, give a good overview of the cluster state
during the test run and can be used to further improve alerting in CI based on existing metrics.

For example, a snapshot can be found in the directory
``gs://cilium-scale-results/logs/scale-100-main/1745287079/artifacts/prometheus_snapshot.tar.gz``.
You need to extract it and run Prometheus locally:

.. code-block:: console

    $ tar xvf ./prometheus_snapshot.tar.gz
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/01JSDJB32JAM1FQ6SN8ESFNDN0/
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/01JSDJB32JAM1FQ6SN8ESFNDN0/meta.json
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/01JSDJB32JAM1FQ6SN8ESFNDN0/tombstones
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/01JSDJB32JAM1FQ6SN8ESFNDN0/index
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/01JSDJB32JAM1FQ6SN8ESFNDN0/chunks/
    prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/01JSDJB32JAM1FQ6SN8ESFNDN0/chunks/000001

    $ prometheus --storage.tsdb.path=./prometheus/snapshots/20250422T013829Z-3ee723086c84c32a/ --web.listen-address="0.0.0.0:9092"

To visualize the data, you can run Grafana locally and connect it to the Prometheus instance.

.. _profiling:

Accessing CPU and memory profiles
"""""""""""""""""""""""""""""""""

All of the scalability tests collect CPU and memory profiles.
They are collected under file names like ``PodPeriodicCommand.*Profiles-stdout.*``.
Each profile is taken periodically during the test run.
The simplest way to visualize them is to leverage `pprof-merge <PPROF_MERGE_>`_.
Example commands to aggregate CPU and memory profiles from the whole test run:

.. code-block:: bash

    gsutil -m cp gs://cilium-scale-results/logs/scale-100-main/1745287079/artifacts/PodPeriodicCommand*Profiles-stdout* ./
    for file in *.txt; do mv "$file" "${file%.txt}.tar.gz"; tar xvf "${file%.txt}.tar.gz"; done
    pprof-merge cilium-bugtool*/cmd/pprof-cpu && mv merged.data cpu.pprof
    pprof-merge cilium-bugtool*/cmd/pprof-heap && mv merged.data heap.pprof
    rm -r cilium-bugtool* PodPeriodicCommand*

Then you can visualize the aggregated CPU and memory profiles by running:

.. code-block:: bash

    go tool pprof -http=localhost:8080 cpu.pprof
    go tool pprof -http=localhost:8080 heap.pprof


If you want to compare the profiles, you can compare them against the baseline extracted from different test run:

.. code-block:: bash

    go tool pprof -http=localhost:8080 --base=baseline_cpu.pprof cpu.pprof
    go tool pprof -http=localhost:8080 --base=baseline_heap.pprof heap.pprof


.. _CL2: https://github.com/kubernetes/perf-tests/tree/master/clusterloader2
.. _CL2_GETTING_STARTED: https://github.com/kubernetes/perf-tests/blob/master/clusterloader2/docs/GETTING_STARTED.md
.. _CL2_README: https://github.com/kubernetes/perf-tests/blob/master/clusterloader2/README.md
.. _CLUSTERMESH_MOCK: https://github.com/cilium/scaffolding/tree/main/cmapisrv-mock
.. _CLUSTERMESH_WORKFLOW: https://github.com/cilium/cilium/blob/main/.github/workflows/scale-test-clustermesh.yaml
.. _EGW_MASQ_METRICS: https://github.com/cilium/cilium/blob/main/.github/actions/cl2-modules/egw/modules/masq-metrics.yaml
.. _EGW_WORKFLOW: https://github.com/cilium/cilium/blob/main/.github/workflows/scale-test-egw.yaml
.. _EXAMPLE_MONITOR: https://github.com/cilium/cilium/blob/main/.github/actions/cl2-modules/egw/prom-extra-podmons/podmonitor.yaml
.. _FQDN_PERF_WORKFLOW: https://github.com/cilium/cilium/blob/main/.github/workflows/fqdn-perf.yaml
.. _GSUTIL_INSTALL: https://cloud.google.com/storage/docs/gsutil_install
.. _NETPOL_SCALE_TEST: https://github.com/cilium/cilium/tree/main/.github/actions/cl2-modules/netpol
.. _PERFDASH: https://github.com/cilium/scaffolding/tree/main/scale-tests
.. _PPROF_MERGE: https://github.com/rakyll/pprof-merge
.. _SCALE_100_WORKFLOW: https://github.com/cilium/cilium/blob/main/.github/workflows/scale-test-100-gce.yaml
.. _SLACK_CHANNEL: https://slack.cilium.io
.. _TEST_RUN: https://github.com/cilium/cilium/actions/workflows/scale-test-100-gce.yaml
.. _UPSTREAM_LOAD_TEST: https://github.com/kubernetes/perf-tests/tree/master/clusterloader2/testing/load
