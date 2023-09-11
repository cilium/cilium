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

Basic Configuration
===================

Configure **Hubble Exporter** with Config Map with a default name of
``cilium-config``. Hubble Exporter is disabled until you set a file path value
for ``hubble-export-file-path``.

.. code-block:: shell-session

    kubectl -n kube-system patch cm cilium-config --patch-file=/dev/stdin <<-EOF
    data:
      hubble-export-file-path: "/var/run/cilium/hubble/events.log"
    EOF

Restart ``cilium-agent`` to apply the change:

.. code-block:: shell-session

    kubectl -n kube-system rollout restart ds/cilium

Verify that the change was applied (it can take a few minutes before the first flow is
logged):

.. code-block:: shell-session

    kubectl -n kube-system exec ds/cilium -- tail -f /var/run/cilium/hubble/events.log

Configure your logging solution to consume logs from your Hubble export file path.

Other configuration options include:

- ``hubble-export-file-max-size-mb``: size in MB at which to rotate the Hubble export file. (default 10)

- ``hubble-export-file-max-backups``: number of rotated Hubble export files to keep. (default 5)

- ``hubble-export-file-compress``: compress rotated Hubble export files. (default false)

Performance tuning
==================

Configuration options impacting performance of **Hubble exporter** include:

- ``hubble-export-allowlist``: specify an allowlist as JSON encoded FlowFilters to Hubble exporter.

- ``hubble-export-denylist``: specify a denylist as JSON encoded FlowFilters to Hubble exporter.

- ``hubble-export-fieldmask``: specify a list of fields to use for field masking in Hubble exporter.

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

   .. code-block:: shell-session

       hubble-export-file-path: "/var/run/cilium/hubble/events.log"
       hubble-export-allowlist: '{"verdict":["DROPPED","ERROR"]}'
       hubble-export-denylist: '{"source_pod":["kube-system/"]},{"destination_pod":["kube-system/"]}'
       hubble-export-fieldmask: time source.namespace source.pod_name destination.namespace destination.pod_name l4 IP node_name is_reply verdict drop_reason_desc

 - Command:

   .. code-block:: shell-session

       kubectl -n kube-system exec ds/cilium -- tail -f /var/run/cilium/hubble/events.log

 - Output:

   ::

       {"flow":{"time":"2023-08-21T12:12:13.517394084Z","verdict":"DROPPED","IP":{"source":"fe80::64d8:8aff:fe72:fc14","destination":"ff02::2","ipVersion":"IPv6"},"l4":{"ICMPv6":{"type":133}},"source":{},"destination":{},"node_name":"kind-kind/kind-worker","drop_reason_desc":"INVALID_SOURCE_IP"},"node_name":"kind-kind/kind-worker","time":"2023-08-21T12:12:13.517394084Z"}
       {"flow":{"time":"2023-08-21T12:12:18.510175415Z","verdict":"DROPPED","IP":{"source":"10.244.1.60","destination":"10.244.1.5","ipVersion":"IPv4"},"l4":{"TCP":{"source_port":44916,"destination_port":80,"flags":{"SYN":true}}},"source":{"namespace":"default","pod_name":"xwing"},"destination":{"namespace":"default","pod_name":"deathstar-7848d6c4d5-th9v2"},"node_name":"kind-kind/kind-worker","drop_reason_desc":"POLICY_DENIED"},"node_name":"kind-kind/kind-worker","time":"2023-08-21T12:12:18.510175415Z"}
