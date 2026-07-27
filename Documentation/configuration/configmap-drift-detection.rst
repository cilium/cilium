.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _configmap-drift-detection:

ConfigMap drift detection
=========================

Many Cilium configuration options require an agent restart to take effect.
After you update the ``cilium-config`` ConfigMap (for example, via
``helm upgrade`` or ``cilium config set``), there is a window where the
running agent's active settings no longer match the desired state in the
ConfigMap. The ConfigMap drift detection feature makes this window observable
by exposing a Prometheus metric that reports how many configuration keys the
agent has not yet applied.

How it works
------------

Drift detection is built on two components:

#. **Dynamic config watcher** (``enable-dynamic-config``): the agent
   continuously watches the ``cilium-config`` ConfigMap via the Kubernetes
   API and reflects its contents into an internal in-memory table. This table
   always represents the desired state.

#. **Drift checker** (``enable-drift-checker``): a background loop compares
   every key in the in-memory table against the agent's active settings, which
   are the values the agent was started with. For each mismatch it logs a
   warning and increments a counter. The counter value is published as the
   ``cilium_drift_checker_config_delta`` Prometheus metric.

A non-zero value of ``cilium_drift_checker_config_delta`` means the running
agent has not yet applied all current ConfigMap changes and needs to be
restarted.

Helm configuration
------------------

The feature is controlled via the ``configDriftDetection`` Helm value group.
Both components are enabled by default:

.. code-block:: yaml

   configDriftDetection:
     enabled: true
     driftChecker: true
     ignoredKeys: []

To ignore specific keys that are intentionally different between the ConfigMap
and the agent's active settings (for example, keys managed externally), set
``ignoredKeys``:

.. code-block:: yaml

   configDriftDetection:
     enabled: true
     driftChecker: true
     ignoredKeys:
       - devices

Prometheus metric
-----------------

When drift detection is enabled, the following metric is available on the agent:

.. list-table::
   :widths: 40 15 45
   :header-rows: 1

   * - Metric name
     - Type
     - Description
   * - ``cilium_drift_checker_config_delta``
     - Gauge
     - Number of ``cilium-config`` ConfigMap keys whose desired value differs
       from the agent's active setting. A value of ``0`` means the agent is
       fully in sync with the ConfigMap.

Interpreting the metric
-----------------------

A value of ``0`` means the agent is fully in sync with the current ConfigMap.
A value greater than ``0`` means one or more configuration keys have been
changed in the ConfigMap but the agent has not yet applied them. Restart the
agent to pick up the changes.

The metric is re-evaluated every time the ConfigMap changes. After you restart
the agent and the agent runs with the updated configuration, the value drops
back to ``0``.
