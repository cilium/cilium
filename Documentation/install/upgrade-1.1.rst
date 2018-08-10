Upgrading to the Cilium 1.1 series
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Upgrading to Cilium 1.1.x from Cilium 1.1.y
"""""""""""""""""""""""""""""""""""""""""""

Set the version to the desired release per :ref:`upgrade_version`.

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

   See the :git-tree:`example ConfigMap
   <examples/kubernetes/templates/v1/cilium-cm.yaml>` for more details.

#. :ref:`upgrade_ds`.
