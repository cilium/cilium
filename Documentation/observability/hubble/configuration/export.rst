.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

***************************
Configuring Hubble exporter
***************************

**Hubble Exporter** is a feature of ``cilium-agent`` that lets you write
Hubble flows to a file for later consumption as logs. Hubble Exporter supports file
rotation, size limits, filters, and field masks.

Prerequisites
=============

.. include:: /installation/k8s-install-download-release.rst

Basic Configuration
===================

Setup
-----

**Hubble Exporter** is enabled with Config Map property. It is disabled
until you set a file path value for ``hubble-export-file-path``.

You can use helm to install cilium with hubble exporter enabled:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --set hubble.enabled=true \\
      --set hubble.export.static.enabled=true \\
      --set hubble.export.static.filePath=/var/run/cilium/hubble/events.log

Wait for ``cilium`` pod to become ready:

.. code-block:: shell-session

    kubectl -n kube-system rollout status ds/cilium

Verify that flow logs are stored in target files:

.. code-block:: shell-session

    kubectl -n kube-system exec ds/cilium -- tail -f /var/run/cilium/hubble/events.log

Once you have configured the Hubble Exporter, you can configure your logging solution to consume
logs from your Hubble export file path.

To get Hubble flows directly exported to the logs instead of written to a rotated file, 
``stdout`` can be defined as ``hubble-export-file-path``.

To disable the static configuration, you must remove the ``hubble-export-file-path`` key in the
``cilium-config`` ConfigMap and manually clean up the log files created in the specified
location in the container. The below command will restart the Cilium pods. If you edit the
ConfigMap manually, you will need to restart the Cilium pods.

.. code-block:: shell-session

    cilium config delete hubble-export-file-path

Configuration options
---------------------

Helm chart configuration options include:

- ``hubble.export.static.filePath``: file path of target log file. (default /var/run/cilium/hubble/events.log)

- ``hubble.export.fileMaxSizeMb``: size in MB at which to rotate the Hubble export file. (default 10)

- ``hubble.export.fileMaxBackups``: number of rotated Hubble export files to keep. (default 5)

Additionally in ``cilium-config`` ConfigMap the following property might be set

- ``hubble-export-file-compress``: compress rotated Hubble export files. (default false)

Performance tuning
==================

Configuration options impacting performance of **Hubble exporter** include:

- ``hubble.export.static.allowList``: specify an allowlist as JSON encoded FlowFilters to Hubble exporter.

- ``hubble.export.static.denyList``: specify a denylist as JSON encoded FlowFilters to Hubble exporter.

- ``hubble.export.static.fieldMask``: specify a list of fields to use for field masking in Hubble exporter.

Filters
-------

You can use ``hubble`` CLI to generated required filters (see `Specifying Raw
Flow Filters`_ for more examples).

.. _Specifying Raw Flow Filters: https://github.com/cilium/hubble#specifying-raw-flow-filters

For example, to filter flows with verdict ``DENIED`` or ``ERROR``, run:

.. code-block:: shell-session

    $ hubble observe --verdict DROPPED --verdict ERROR --print-raw-filters
    allowlist:
    - '{"verdict":["DROPPED","ERROR"]}'

Then paste the output to ``hubble-export-allowlist`` in ``cilium-config``
Config Map:

.. code-block:: shell-session

    kubectl -n kube-system patch cm cilium-config --patch-file=/dev/stdin <<-EOF
    data:
      hubble-export-allowlist: '{"verdict":["DROPPED","ERROR"]}'
    EOF

Or use helm chart to update your cilium installation setting value flag
``hubble.export.static.allowList``.

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
      --set hubble.enabled=true \\
      --set hubble.export.static.enabled=true \\
      --set hubble.export.static.allowList[0]='{"verdict":["DROPPED","ERROR"]}'


You can do the same to selectively filter data. For example, to filter all flows in the
``kube-system`` namespace, run:

.. code-block:: shell-session

    $ hubble observe --not --namespace kube-system --print-raw-filters
    denylist:
    - '{"source_pod":["kube-system/"]}'
    - '{"destination_pod":["kube-system/"]}'

Then paste the output to ``hubble-export-denylist`` in ``cilium-config`` Config
Map:

.. code-block:: shell-session

    kubectl -n kube-system patch cm cilium-config --patch-file=/dev/stdin <<-EOF
    data:
      hubble-export-denylist: '{"source_pod":["kube-system/"]},{"destination_pod":["kube-system/"]}'
    EOF

Or use helm chart to update your cilium installation setting value flag
``hubble.export.static.denyList``.

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
      --set hubble.enabled=true \\
      --set hubble.export.static.enabled=true \\
      --set hubble.export.static.denyList[0]='{"source_pod":["kube-system/"]}' \\
      --set hubble.export.static.denyList[1]='{"destination_pod":["kube-system/"]}'

Field mask
----------

Field mask can't be generated with ``hubble``. Field mask is a list of field
names from the `flow proto`_ definition.

.. _flow proto: https://github.com/cilium/cilium/blob/main/api/v1/flow/flow.proto

Examples include:

 - To keep all information except pod labels:

   .. code-block:: shell-session

       hubble-export-fieldmask: time source.identity source.namespace source.pod_name destination.identity destination.namespace destination.pod_name source_service destination_service l4 IP ethernet l7 Type node_name is_reply event_type verdict Summary

 - To keep only timestamp, verdict, ports, IP addresses, node name, pod name, and namespace:

   .. code-block:: shell-session

       hubble-export-fieldmask: time source.namespace source.pod_name destination.namespace destination.pod_name l4 IP node_name is_reply verdict

The following is a complete example of configuring Hubble Exporter.

 - Configuration:

   .. parsed-literal::

       helm upgrade cilium |CHART_RELEASE| \\
          --set hubble.enabled=true \\
          --set hubble.export.static.enabled=true \\
          --set hubble.export.static.filePath=/var/run/cilium/hubble/events.log \\
          --set hubble.export.static.allowList[0]='{"verdict":["DROPPED","ERROR"]}'
          --set hubble.export.static.denyList[0]='{"source_pod":["kube-system/"]}' \\
          --set hubble.export.static.denyList[1]='{"destination_pod":["kube-system/"]}' \\
          --set "hubble.export.static.fieldMask={time,source.namespace,source.pod_name,destination.namespace,destination.pod_name,l4,IP,node_name,is_reply,verdict,drop_reason_desc}"

 - Command:

   .. code-block:: shell-session

       kubectl -n kube-system exec ds/cilium -- tail -f /var/run/cilium/hubble/events.log

 - Output:

   ::

       {"flow":{"time":"2023-08-21T12:12:13.517394084Z","verdict":"DROPPED","IP":{"source":"fe80::64d8:8aff:fe72:fc14","destination":"ff02::2","ipVersion":"IPv6"},"l4":{"ICMPv6":{"type":133}},"source":{},"destination":{},"node_name":"kind-kind/kind-worker","drop_reason_desc":"INVALID_SOURCE_IP"},"node_name":"kind-kind/kind-worker","time":"2023-08-21T12:12:13.517394084Z"}
       {"flow":{"time":"2023-08-21T12:12:18.510175415Z","verdict":"DROPPED","IP":{"source":"10.244.1.60","destination":"10.244.1.5","ipVersion":"IPv4"},"l4":{"TCP":{"source_port":44916,"destination_port":80,"flags":{"SYN":true}}},"source":{"namespace":"default","pod_name":"xwing"},"destination":{"namespace":"default","pod_name":"deathstar-7848d6c4d5-th9v2"},"node_name":"kind-kind/kind-worker","drop_reason_desc":"POLICY_DENIED"},"node_name":"kind-kind/kind-worker","time":"2023-08-21T12:12:18.510175415Z"}


Dynamic exporter configuration
==============================

Standard hubble exporter configuration accepts only one set of filters and
requires cilium pod restart to change config. Dynamic flow logs allow configuring
multiple filters at the same time and saving output in separate files.
Additionally it does not require cilium pod restarts to apply changed configuration.

**Dynamic Hubble Exporter** is enabled with Config Map property. It is disabled
until you set a file path value for ``hubble-flowlogs-config-path``.

Install cilium with dynamic exporter enabled:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --set hubble.enabled=true \\
      --set hubble.export.dynamic.enabled=true

Wait for ``cilium`` pod to become ready:

.. code-block:: shell-session

    kubectl -n kube-system rollout status ds/cilium

You can change flow log settings without a need for pod to be restarted
(changes should be reflected within 60s because of configmap propagation delay):

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
      --set hubble.enabled=true \\
      --set hubble.export.dynamic.enabled=true \\
      --set hubble.export.dynamic.config.content[0].name=system \\
      --set hubble.export.dynamic.config.content[0].filePath=/var/run/cilium/hubble/events-system.log \\
      --set hubble.export.dynamic.config.content[0].includeFilters[0].source_pod[0]='kube_system/' \\
      --set hubble.export.dynamic.config.content[0].includeFilters[1].destination_pod[0]='kube_system/'


Dynamic flow logs can be configured with ``end`` property which means that it will
automatically stop logging after specified date time. It supports the same
field masking and filtering as static hubble exporter.

For max output file size and backup files dynamic exporter reuses the same
settings as static one: ``hubble.export.fileMaxSizeMb`` and ``hubble.export.fileMaxBackups``

Sample dynamic flow logs configs:

::

  hubble:
    export:
      dynamic:
        enabled: true
        config:
          enabled: true
          content:
          - name: "test001"
            filePath: "/var/run/cilium/hubble/test001.log"
            fieldMask: []
            includeFilters: []
            excludeFilters: []
            end: "2023-10-09T23:59:59-07:00"
          - name: "test002"
            filePath: "/var/run/cilium/hubble/test002.log"
            fieldMask: ["source.namespace", "source.pod_name", "destination.namespace", "destination.pod_name", "verdict"]
            includeFilters:
            - source_pod: ["default/"]
              event_type:
              - type: 1
            - destination_pod: ["frontend/webserver-975996d4c-7hhgt"]
            excludeFilters: []
            end: "2023-10-09T23:59:59-07:00"
          - name: "test003"
            filePath: "/var/run/cilium/hubble/test003.log"
            fieldMask: ["source", "destination","verdict"]
            includeFilters: []
            excludeFilters:
            - destination_pod: ["ingress/"]