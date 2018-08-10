Upgrading to the Cilium 1.1 series
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The latest version in the Cilium 1.1 series can be found `here <https://raw.githubusercontent.com/cilium/cilium/v1.1/VERSION>`__

Upgrading to Cilium 1.1.x from Cilium 1.1.y
"""""""""""""""""""""""""""""""""""""""""""

.. include:: upgrade-micro.rst

Upgrading to Cilium 1.1.x from Cilium 1.0.y
"""""""""""""""""""""""""""""""""""""""""""

#. Follow the guide in :ref:`err_low_mtu` to update the MTU of existing
   endpoints.

#. :ref:`upgrade_cm`.

   New options in Cilium 1.1:

   * ``legacy-host-allows-world``: This is recommended to be set to false. For
     more information, see :ref:`host_vs_world`.
   * ``sidecar-istio-proxy-image``

   Deprecated options in Cilium 1.1:

   * ``sidecar-http-proxy``

   See the `example Cilium 1.1 ConfigMap
   <https://raw.githubusercontent.com/cilium/cilium/v1.1/examples/kubernetes/templates/v1/cilium-cm.yaml>`__
   for more details.

#.

  .. include:: upgrade-minor.rst
