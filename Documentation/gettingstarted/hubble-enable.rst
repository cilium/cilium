Enable Hubble
==============

Hubble is a fully distributed networking and security observability platform
for cloud native workloads. It is built on top of Cilium and eBPF to enable
deep visibility into the communication and behavior of services as well as the
networking infrastructure in a completely transparent manner.

* Hubble can be configured to be in **local mode** or **distributed mode (beta)**.

  .. tabs::

     .. group-tab:: Local Mode

        In **local mode**, Hubble listens on a UNIX domain socket. You can connect to a
        Hubble instance by running ``hubble`` command from inside the Cilium pod. This
        provides networking visibility for traffic observed by the local Cilium agent.

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set global.hubble.enabled=true \\
              --set global.hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"

     .. group-tab:: Distributed Mode (beta)


        In **distributed mode (beta)**, Hubble listens on a TCP port on the host network.
        This allows :ref:`hubble_relay` to communicate with all the Hubble instances in
        the cluster. Hubble CLI and Hubble UI in turn connect to Hubble Relay to provide
        cluster-wide networking visibility.

        .. warning::

           In Distributed mode, Hubble runs a gRPC service over plain-text HTTP on the host
           network without any authentication/authorization. The main consequence is that
           anybody who can reach the Hubble gRPC service can obtain all the networking
           metadata from the host. It is therefore **strongly discouraged** to enable
           distributed mode in a production environment.

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set global.hubble.enabled=true \\
              --set global.hubble.listenAddress=":4244" \\
              --set global.hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \\
              --set global.hubble.relay.enabled=true \\
              --set global.hubble.ui.enabled=true

* Restart the Cilium daemonset to allow Cilium agent to pick up the ConfigMap changes:

  .. parsed-literal::

      kubectl rollout restart -n $CILIUM_NAMESPACE ds/cilium

* To pick one Cilium instance and validate that Hubble is properly configured to listen on
  a UNIX domain socket:

  .. parsed-literal::

      kubectl exec -n $CILIUM_NAMESPACE -t ds/cilium -- hubble observe

* **(Distributed mode only)** To validate that Hubble Relay is running, install the ``hubble``
  CLI:

  .. include:: hubble-install.rst

  Once the ``hubble`` CLI is installed, set up a port forwarding for ``hubble-relay`` service and
  run ``hubble observe`` command:

  .. parsed-literal::

      kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-relay 4245:80
      hubble observe --server localhost:4245

  (**For Linux / MacOS**) For convenience, you may set and export the ``HUBBLE_DEFAULT_SOCKET_PATH``
  environment variable:

  .. code:: bash

    $ export HUBBLE_DEFAULT_SOCKET_PATH=localhost:4245

  This will allow you to use ``hubble status`` and ``hubble observe`` commands
  without having to specify the server address via the ``--server`` flag.

* **(Distributed mode only)** To validate that Hubble UI is properly configured, set up a port forwarding for
  ``hubble-ui`` service:

  .. parsed-literal::

      kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-ui 12000:80

  and then open http://localhost:12000/.
