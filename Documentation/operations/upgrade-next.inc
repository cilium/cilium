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

* TODO

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

Removed Options
###############

The following options were previously deprecated, and they are now removed
from Cilium.

* The ``--aws-use-primary-address`` operator flag has been removed. Whether an
  ENI's primary IP is available for pod allocation is now determined per node by
  the ``spec.eni.use-primary-address`` field of the ``CiliumNode`` resource,
  which is populated from the ``--eni-use-primary-address`` agent flag (Helm
  value ``eni.nodeSpec.usePrimaryAddress``). This makes the CiliumNode spec the
  single source of truth and removes the possibility of the operator-wide flag
  disagreeing with the per-node value. Deployments configured through the Helm
  chart are unaffected, as the chart only ever wired the agent-side value. If
  you passed ``--aws-use-primary-address`` directly on the operator, set
  ``eni.nodeSpec.usePrimaryAddress=true`` (equivalently, the
  ``--eni-use-primary-address`` agent flag) instead to retain the same behavior.

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
