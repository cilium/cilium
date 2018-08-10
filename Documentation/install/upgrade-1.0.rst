Upgrading to the Cilium 1.0 series
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The latest version in the Cilium 1.0 series can be found `here <https://raw.githubusercontent.com/cilium/cilium/v1.0/VERSION>`__

Upgrading to Cilium 1.0.x from Cilium 1.0.y
"""""""""""""""""""""""""""""""""""""""""""

.. include:: upgrade-micro.rst

Upgrading to Cilium 1.0.x from older versions
"""""""""""""""""""""""""""""""""""""""""""""

Versions of Cilium older than 1.0.0 are unsupported for upgrade. The
:ref:`upgrade_general` may work, however it may be more reliable to start
again from the :ref:`install_guide`.

Downgrading to Cilium 1.0.x from Cilium 1.1.y
"""""""""""""""""""""""""""""""""""""""""""""

#. Check whether you have any CIDR policy rules installed:

   .. code-block:: shell-session

     $ kubectl get cnp --all-namespaces -o yaml | grep "/0"

   If any CIDR rules match on the CIDR prefix ``/0``, these must be removed
   prior to downgrade as these rules are not supported by Cilium 1.0.

#.

  .. include:: upgrade-minor.rst

Downgrading to Cilium 1.0.x from Cilium 1.0.y
"""""""""""""""""""""""""""""""""""""""""""""

.. include:: upgrade-micro.rst
