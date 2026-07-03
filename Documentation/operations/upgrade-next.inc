.. _next_release_required_changes:

|NEXT_RELEASE| Upgrade Notes
----------------------------

Action Required
~~~~~~~~~~~~~~~

If you are using the following features in your environment, then you may need
to take action because of changes to the behavior of these features. Read the
notes carefully below to understand what to do during upgrade.

* TODO

Informational Notes
~~~~~~~~~~~~~~~~~~~

* TODO

Changes to Features
~~~~~~~~~~~~~~~~~~~

New Options
###########

The following options have been introduced in this version of Cilium:

* ``CiliumPodIPPool`` gained the ``spec.ipv4.pool`` and ``spec.ipv6.pool``
  fields, which carry per-CIDR configuration. Each entry references a CIDR from
  ``cidrs`` and may set ``reservedRanges`` to exclude IP ranges from allocation.
  These fields are only available in ``cilium.io/v2``. See
  :ref:`update_existing_ciliumpodippools_with_reservedranges`.

Changed Options
###############

The following options have been modified in this version of Cilium to behave
differently than in prior releases:

* TODO

Deprecated Options
##################

The following options have been deprecated in this version of Cilium. A future
version of Cilium will remove these options, so if you use these options then
you may need to take action to migrate to an alternative.

* Node encryption, enabled with ``encryption.nodeEncryption`` and only
  compatible with WireGuard, is deprecated and will be removed in v1.22. Please
  reach out if you are interested to maintain this feature.

* The ``cilium.io/v2alpha1`` API version of ``CiliumPodIPPool`` is deprecated
  and will be removed in a future release. ``cilium.io/v2`` is now the storage
  version. Update existing manifests or tooling that references
  ``cilium.io/v2alpha1`` to use ``cilium.io/v2`` instead.

Removed Options
###############

The following options were previously deprecated, and they are now removed
from Cilium.

* TODO

Changes to Metrics
~~~~~~~~~~~~~~~~~~

Added Metrics
#############

* TODO

Changed Metrics
###############

* TODO

Deprecated Metrics
##################

* TODO

Removed Metrics
###############

* TODO
