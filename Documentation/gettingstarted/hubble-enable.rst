Enable Hubble for Cluster-Wide Visibility
=========================================

Hubble is the component for observability in Cilium. To obtain cluster-wide
visibility into your network traffic, deploy Hubble Relay and the UI as follows
on your existing installation:

.. tabs::

    .. group-tab:: Installation via Helm

        If you installed Cilium via ``helm install``, you may enable Hubble
        Relay and UI with the following command:

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set hubble.relay.enabled=true \\
              --set hubble.ui.enabled=true

    .. group-tab:: Installation via ``quick-hubble-install.yaml``

        If you installed Cilium via the provided ``quick-install.yaml``,
        you may deploy Hubble Relay and UI on top of your existing installation
        with the following command:

        .. parsed-literal::

            kubectl apply -f |SCM_WEB|/install/kubernetes/quick-hubble-install.yaml

Once the Hubble UI pod is started, use port forwarding for the ``hubble-ui``
service. This allows opening the UI locally on a browser:

.. code:: bash

   kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-ui --address 0.0.0.0 --address :: 12000:80

And then open http://localhost:12000/ to access the UI.

Hubble UI is not the only way to get access to Hubble data. A command line
tool, the Hubble CLI, is also available. It can be installed by following the
instructions below:

.. include:: hubble-install.rst

Similarly to the UI, use port forwarding for the ``hubble-relay`` service to
make it available locally:

.. code:: bash

   kubectl port-forward -n $CILIUM_NAMESPACE svc/hubble-relay --address 0.0.0.0 --address :: 4245:80

In a separate terminal window, run the ``hubble status`` command specifying the
Hubble Relay address:

.. code:: shell-session

   $ hubble --server localhost:4245 status
   Healthcheck (via localhost:4245): Ok
   Current/Max Flows: 5455/16384 (33.29%)
   Flows/s: 11.30
   Connected Nodes: 4/4

If Hubble Relay reports that all nodes are connected, as in the example output
above, you can now use the CLI to observe flows of the entire cluster:

.. code:: bash

   hubble --server localhost:4245 observe

If you encounter any problem at this point, you may seek help on :ref:`slack`.

.. tip::
   Hubble CLI configuration can be persisted using a configuration file or
   environment variables. This avoids having to specify options specific to a
   particular environment every time a command is run. Run ``hubble help
   config`` for more information.

For more information about Hubble and its components, see the
:ref:`concepts_observability` section.