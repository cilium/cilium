Upgrading to the Cilium 1.2 series
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The latest version in the Cilium 1.2 series can be found `here <https://raw.githubusercontent.com/cilium/cilium/v1.2/VERSION>`__

Upgrading to Cilium 1.2.x from Cilium 1.2.y
"""""""""""""""""""""""""""""""""""""""""""

.. include:: upgrade-micro.rst

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
