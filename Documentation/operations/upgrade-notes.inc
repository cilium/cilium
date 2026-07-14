.. _version_notes:
.. _upgrade_version_specifics:

Version Specific Notes
======================

This section details the upgrade notes specific to |CURRENT_RELEASE|. Read them
carefully and take the suggested actions before upgrading Cilium to |CURRENT_RELEASE|.
For upgrades to earlier releases, see the
:prev-docs:`upgrade notes to the previous version <operations/upgrade/#upgrade-notes>`.

The only tested upgrade and rollback path is between consecutive minor releases.
Always perform upgrades and rollbacks between one minor release at a time.
Additionally, always update to the latest patch release of your current version
before attempting an upgrade.

Tested upgrades are expected to have minimal to no impact on new and existing
connections matched by either no Network Policies, or L3/L4 Network Policies only.
Any traffic flowing via user space proxies (for example, because an L7 policy is
in place, or using Ingress/Gateway API) will be disrupted during upgrade. Endpoints
communicating via the proxy must reconnect to re-establish connections.

.. include:: upgrade-next.inc
.. include:: upgrade-current.inc
