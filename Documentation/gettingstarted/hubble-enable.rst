Enable Hubble
==============

Hubble is a fully distributed networking and security observability platform
for cloud native workloads. It is built on top of Cilium and eBPF to enable
deep visibility into the communication and behavior of services as well as the
networking infrastructure in a completely transparent manner.

* Hubble can be configured to be in **distributed mode** or **local mode**.

  .. tabs::

     .. group-tab:: Distributed Mode


        In **distributed mode**, Hubble listens on a TCP port on the host network.
        This allows :ref:`hubble_relay` to communicate with all the Hubble instances in
        the cluster. Hubble CLI and Hubble UI in turn connect to Hubble Relay to provide
        cluster-wide networking visibility.

        .. note::

           In Distributed mode, Hubble runs a gRPC service over HTTP on the
           host network. It is secured using mutual TLS (mTLS) by default to
           only allow access to Hubble Relay. Refer to
           :ref:`hubble_configure_tls_certs` to manually provide TLS certificates.

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set hubble.enabled=true \\
              --set hubble.listenAddress=":4244" \\
              --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \\
              --set hubble.relay.enabled=true \\
              --set hubble.ui.enabled=true

     .. group-tab:: Local Mode

        In **local mode**, Hubble listens on a UNIX domain socket. You can connect to a
        Hubble instance by running ``hubble`` command from inside the Cilium pod. This
        provides networking visibility for traffic observed by the local Cilium agent.

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set hubble.enabled=true \\
              --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"

* Restart the Cilium daemonset to allow Cilium agent to pick up the ConfigMap changes:

   .. code:: bash

      kubectl rollout restart -n $CILIUM_NAMESPACE ds/cilium

* To pick one Cilium instance and validate that Hubble is properly configured to listen on
  a UNIX domain socket:

   .. code:: bash

      kubectl exec -n $CILIUM_NAMESPACE -t ds/cilium -- hubble observe

* **(Distributed mode only)** To validate that Hubble Relay is running, install the ``hubble``
  CLI:

  .. include:: hubble-install.rst

  Once the ``hubble`` CLI is installed, set up a port forwarding for ``hubble-relay`` service and
  run ``hubble observe`` command:

   .. code:: bash

      kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-relay --address 0.0.0.0 --address :: 4245:80
      hubble observe --server localhost:4245

  (**For Linux / MacOS**) For convenience, you may set and export the ``HUBBLE_SERVER``
  environment variable:

   .. code:: bash

      export HUBBLE_SERVER=localhost:4245

  This will allow you to use ``hubble status`` and ``hubble observe`` commands
  without having to specify the server address via the ``--server`` flag.

* **(Distributed mode only)** To validate that Hubble UI is properly configured, set up a port forwarding for
  ``hubble-ui`` service:

  .. code:: bash

      kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-ui --address 0.0.0.0 --address :: 12000:80

  and then open http://localhost:12000/.
