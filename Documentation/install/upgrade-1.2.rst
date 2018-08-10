Upgrading to the Cilium 1.2 series
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Upgrading to Cilium 1.2.x from Cilium 1.2.y
"""""""""""""""""""""""""""""""""""""""""""

Set the version to the desired release per :ref:`upgrade_version`.

Upgrading to Cilium 1.2.x from Cilium 1.1.y or 1.0.z
""""""""""""""""""""""""""""""""""""""""""""""""""""

#. Upgrade to Cilium ``1.1.3`` or later using the instructions below.

#. :ref:`upgrade_cm`.

   New options in Cilium 1.2:

   * ``cluster-name``
   * ``cluster-id``
   * ``monitor-aggregation-level``

   See the :git-tree:`example ConfigMap
   <examples/kubernetes/templates/v1/cilium-cm.yaml>` for more details.

#. :ref:`upgrade_ds`.
