.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_upgrade:

*************
Upgrade Guide
*************

.. _upgrade_general:

This upgrade guide is intended for Cilium 1.0 or later running on Kubernetes.
It is assuming that Cilium has been deployed using standard procedures as
described in the :ref:`k8s_concepts_deployment`. If you have installed Cilium
using the guide :ref:`ds_deploy`, then this is automatically the case.

Running a pre-flight DaemonSet
==============================

.. _pre_flight:

When rolling out an upgrade with Kubernetes, Kubernetes will first terminate the
pod followed by pulling the new image version and then finally spin up the new
image. In order to reduce the downtime of the agent, the new image version can
be pre-pulled. It also verifies that the new image version can be pulled and
avoids ErrImagePull errors during the rollout.

.. tabs::
  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-pre-flight.yaml


After running the cilium-pre-flight.yaml, make sure the number of READY pods
is the same number of Cilium pods running.

.. code-block:: shell-session

    kubectl get daemonset -n kube-system | grep cilium
    NAME                      DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
    cilium                    2         2         2       2            2           <none>          1h20m
    cilium-pre-flight-check   2         2         2       2            2           <none>          7m15s

Once the number of READY pods are the same, you can delete cilium-pre-flight-check
`DaemonSet` and proceed with the upgrade.

.. code-block:: shell-session

      kubectl -n kube-system delete ds cilium-pre-flight-check

.. _upgrade_micro:

Upgrading Micro Versions
========================

Micro versions within a particular minor version, e.g. 1.2.x -> 1.2.y, are
always 100% compatible for both up- and downgrades. Upgrading or downgrading is
as simple as changing the image tag version in the `DaemonSet` file:

.. code-block:: shell-session

    kubectl -n kube-system set image daemonset/cilium cilium-agent=docker.io/cilium/cilium:vX.Y.Z
    kubectl -n kube-system rollout status daemonset/cilium

Kubernetes will automatically restart all Cilium according to the
``UpgradeStrategy`` specified in the `DaemonSet`.

.. note::

    Direct version upgrade between minor versions is not recommended as RBAC
    and DaemonSet definitions are subject to change between minor versions.
    See :ref:`upgrade_minor` for instructions on how to up or downgrade between
    different minor versions.

.. _upgrade_minor:

Upgrading Minor Versions
========================

Step 1: Upgrade to latest micro version (Recommended)
-----------------------------------------------------

When upgrading from one minor release to another minor release, for example 1.x
to 1.y, it is recommended to first upgrade to the latest micro release of the
currently running minor release. This ensures that downgrading by rolling back
on a failed minor release upgrade is always possible and seamless.

Step 2: Upgrade the ConfigMap (Optional)
----------------------------------------

The configuration of Cilium is stored in a `ConfigMap` called
``cilium-config``.  The format is compatible between minor releases so
configuration parameters are automatically preserved across upgrades.  However,
new minor releases may introduce new functionality that require opt-in via the
`ConfigMap`. Refer to the :ref:`upgrade_version_specifics` for a list of new
configuration options for each minor version.

Refer to the section :ref:`upgrade_configmap` for instructions on how to
upgrade a `ConfigMap` to the latest template while preserving your
configuration parameters.

Step 3: Apply new RBAC and DaemonSet definitions
------------------------------------------------

As minor versions typically introduce new functionality which require changes
to the `DaemonSet` and `RBAC` definitions, the YAML definitions have to be
upgraded. The following links refer to version specific DaemonSet files which
automatically 

Both files are dedicated to "\ |SCM_BRANCH|" for each Kubernetes version.

.. tabs::
  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-ds.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-ds.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-ds.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-ds.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-ds.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-ds.yaml

Below we will show examples of how Cilium should be upgraded using Kubernetes
rolling upgrade functionality in order to preserve any existing Cilium
configuration changes (e.g., etc configuration) and minimize network
disruptions for running workloads. These instructions upgrade Cilium to version
"\ |SCM_BRANCH|" by updating the ``ConfigMap``, ``RBAC`` rules and
``DaemonSet`` files separately. Rather than installing all configuration in one
``cilium.yaml`` file, which could override any custom ``ConfigMap``
configuration, installing these files separately allows upgrade to be staged
and for user configuration to not be affected by the upgrade.

Rolling Back
============

Occasionally, it may be necessary to undo the rollout because a step was missed
or something went wrong during upgrade. To undo the rollout, change the image
tag back to the previous version or undo the rollout using ``kubectl``:

.. code-block:: shell-session

    $ kubectl rollout undo daemonset/cilium -n kube-system

This will revert the latest changes to the Cilium ``DaemonSet`` and return
Cilium to the state it was in prior to the upgrade.

.. note::

    When rolling back after new features of the new minor version have already
    been consumed, consult an eventual existing downgrade section in the
    :ref:`version_notes` to check and prepare for incompatible feature use
    before downgrading/rolling back. This step is only required after new
    functionality introduced in the new minor version has already been
    explicitly used by importing policy or by opting into new features via the
    `ConfigMap`.

.. _version_notes:
.. _upgrade_version_specifics:

Version Specific Notes
======================

This section documents the specific steps required for upgrading from one
version of Cilium to another version of Cilium. There are particular version
transitions which are suggested by the Cilium developers to avoid known issues
during upgrade, then subsequently there are sections for specific upgrade
transitions, ordered by version.

The table below lists suggested upgrade transitions, from a specified current
version running in a cluster to a specified target version. If a specific
combination is not listed in the table below, then it may not be safe. In that
case, consider staging the upgrade, for example upgrading from ``1.1.x`` to the
latest ``1.1.y`` release before subsequently upgrading to ``1.2.z``.

+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| Current version       | Target version        | ``DaemonSet`` upgrade | L3 impact               | L7 impact                 |
+=======================+=======================+=======================+=========================+===========================+
| ``1.0.x``             | ``1.1.y``             | Required              | N/A                     | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.1.x``             | ``1.2.y``             | Required              | Temporary disruption[2] | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.2.x``             | ``1.3.y``             | Required              | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

#. **Temporary disruption**: All traffic may be temporarily disrupted during
   upgrade. Connections should successfully re-establish without requiring
   clients to reconnect.

1.3 Upgrade Notes
-----------------

Upgrading from 1.2.x to 1.3.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. If you are running Cilium 1.0.x or 1.1.x, please upgrade to 1.2.x first. It
   is also possible to upgrade from 1.0 or 1.1 directly to 1.3 by combining the
   upgrade instructions for each minor release. See :ref:`1.2_upgrade_notes`.

#. Upgrade to Cilium ``1.2.4`` or later using the guide :ref:`upgrade_micro`.

#. Follow the standard procedures to perform the upgrade as described in :ref:`upgrade_minor`.

.. _1.3_new_options:

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

  * ``ct-global-max-entries-tcp/ct-global-max-entries-other:`` Specifies the
    maximum number of connections supported across all endpoints, split by
    protocol: tcp or other. One pair of maps uses these values for IPv4
    connections, and another pair of maps use these values for IPv6
    connections. If these values are modified, then during the next Cilium
    startup the tracking of ongoing connections may be disrupted. This may lead
    to brief policy drops or a change in loadbalancing decisions for a
    connection.

  *  ``clean-cilium-bpf-state``: Similar to ``clean-cilium-state`` but only
     cleans the BPF state while preserving all other state. Endpoints will
     still be restored and IP allocations will prevail but all datapath state
     is cleaned when Cilium starts up. Not required for normal operation.

.. _1.2_upgrade_notes:

1.2 Upgrade Notes
-----------------

.. _1.2_new_options:

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

   * ``cluster-name``: Name of the cluster. Only relevant when building a mesh
     of clusters.

   * ``cluster-id``: Unique ID of the cluster. Must be unique across all
     connected clusters and in the range of 1 and 255. Only relevant when
     building a mesh of clusters.

   * ``monitor-aggregation-level``: If you want cilium monitor to aggregate
     tracing for packets, set this level to "low", "medium", or "maximum". The
     higher the level, the less packets that will be seen in monitor output.

Upgrade Impact
~~~~~~~~~~~~~~

.. note::

  Due to a format change in datapath structures to improve scale, the
  connection tracking table will be cleared when the new version starts up for
  the first time. This will cause a temporary disruption. All existing
  connections are temporarily but should successfully re-establish without
  requiring clients to reconnect.

Upgrading to 1.2.x from 1.1.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. If you are running Cilium 1.0.x. Please consider upgrading to 1.1.x first.
   At the very least, be aware that all :ref:`1.1_upgrade_notes` will apply as
   well.

#. Upgrade to Cilium ``1.1.4`` or later using the guide :ref:`upgrade_micro`.

#. Consider the new `ConfigMap` options described in section :ref:`1.2_new_options`.

#. Follow the standard procedures to perform the upgrade as described in :ref:`upgrade_minor`.

.. _1.1_upgrade_notes:

1.1 Upgrade Notes
-----------------

.. _1.1_new_options:

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

* ``legacy-host-allows-world``: In Cilium 1.0, all traffic from the host,
  including from local processes and traffic that is masqueraded from the
  outside world to the host IP, would be classified as from the ``host`` entity
  (``reserved:host`` label).  Furthermore, to allow Kubernetes agents to
  perform health checks over IP into the endpoints, the host is allowed by
  default. This means that all traffic from the outside world is also allowed
  by default, regardless of security policy. This behavior is continued to
  maintain backwards compatible but it can be disabled (recommended) by setting
  ``legacy-host-allows-world`` to ``false``. See :ref:`host_vs_world` for more
  details.

* ``sidecar-istio-proxy-image:`` Regular expression matching compatible Istio
  sidecar istio-proxy container image names.


Deprecated Options
~~~~~~~~~~~~~~~~~~

* ``sidecar-http-proxy``

Upgrading to Cilium 1.1.x from Cilium 1.0.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Consider the new `ConfigMap` options described in section :ref:`1.1_new_options`.

#. Follow the guide in :ref:`err_low_mtu` to update the MTU of existing
   endpoints to the new improved model. This step can also be performed after
   the upgrade but performing it before the upgrade will guarantee that no
   packet loss occurs during the upgrade phase.

#. Follow the standard procedures to perform the upgrade as described in :ref:`upgrade_minor`.


Downgrading to Cilium 1.1.x from Cilium 1.2.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When downgrading from Cilium 1.2, the target version **must** be Cilium 1.1.4
or later.

#. Check whether you have any DNS policy rules installed:

   .. code-block:: shell-session

     $ kubectl get cnp --all-namespaces -o yaml | grep "fqdn"

   If any DNS rules exist, these must be removed prior to downgrade as these
   rules are not supported by Cilium 1.1.

.. _err_low_mtu:

MTU handling behavior change in Cilium 1.1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cilium 1.0 by default configured the MTU of all Cilium-related devices and
endpoint devices to 1450 bytes, to guarantee that packets sent from an endpoint
would remain below the MTU of a tunnel. This had the side-effect that when a
Cilium-managed pod made a request to an outside (world) IP, if the response
came back in 1500B chunks, then it would be fragmented when transmitted to the
``cilium_host`` device. These fragments then pass through the Cilium policy
logic. Latter IP fragments would not contain L4 ports, so if any L4 or L4+L7
policy was applied to the destination endpoint, then the fragments would be
dropped. This could cause disruption to network traffic.

Affected versions
^^^^^^^^^^^^^^^^^

* Cilium 1.0 or earlier.

Cilium 1.1 and later are not affected.

Mitigation
^^^^^^^^^^

There is no known mitigation for users running Cilium 1.0 at this time.

Solution
^^^^^^^^

Cilium 1.1 fixes the above issue by increasing the MTU of the Cilium-related
devices and endpoint devices to 1500B (or larger based on container runtime
settings), then configuring a route within the endpoint at a lower MTU to
ensure that transmitted packets will fit within tunnel encapsulation. This
addresses the above issue for all new pods.

The MTU for endpoints deployed on Cilium 1.0 must be updated to remediate this
issue. Users are recommended to follow the below upgrade instructions prior to
upgrading to Cilium 1.1 to prepare the endpoints for the new MTU behavior.

Upgrade Steps
^^^^^^^^^^^^^

The `mtu-update`_ tool is provided as a Kubernetes `DaemonSet` to assist the
live migration of applications from the Cilium 1.0 MTU handling behavior to the
Cilium 1.1 or later MTU handling behavior. To prevent any packet loss during
upgrade, these steps should be followed before upgrading to Cilium 1.1;
however, they are also safe to run after upgrade.

To deploy the `mtu-update`_ DaemonSet:

.. code-block:: shell-session

  $ kubectl create -f https://raw.githubusercontent.com/cilium/mtu-update/v1.1/mtu-update.yaml

This will deploy the `mtu-update`_ daemon on each node in your cluster, where it
will proceed to search for Cilium-managed pods and update the MTU inside these
pods to match the Cilium 1.1 behavior.

To determine whether this was successful:

.. code-block:: shell-session

  $ kubectl get ds mtu-update -n kube-system
  NAME         DESIRED   CURRENT   READY     UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
  mtu-update   1         1         1         1            1           <none>          18s

When the ``DESIRED`` count matches the ``READY`` count, the MTU has been
successfully updated for running pods. It is now safe to remove the
`mtu-update`_ daemonset:

.. code-block:: shell-session

  $ kubectl delete -f https://raw.githubusercontent.com/cilium/mtu-update/v1.1/mtu-update.yaml

For more information, visit the `mtu-update`_ website.

.. _mtu-update: https://github.com/cilium/mtu-update


1.0 Upgrade Notes
-----------------

Upgrading to Cilium 1.0.x from older versions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Versions of Cilium older than 1.0.0 are unsupported for upgrade. The
:ref:`upgrade_minor` may work, however it may be more reliable to start again
from the :ref:`install_guide`.

Downgrading to Cilium 1.0.x from Cilium 1.1.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check whether you have any CIDR policy rules not compatible with 1.0.x:

   .. code-block:: shell-session

     $ kubectl get cnp --all-namespaces -o yaml

   * **Default prefix:** If any CIDR rules match on the CIDR prefix ``/0``,
     these must be removed prior to downgrade as these rules are not supported
     by Cilium 1.0. (`PR 4458 <https://github.com/cilium/cilium/pull/4458>`_)

   * **CIDR-dependent L4 policies:** If any CIDR rules also specify a
     ``toPorts`` section, these must be removed prior to downgrade as these
     rules are not supported by Cilium 1.0. (`PR 3835 <https://github.com/cilium/cilium/pull/3835>`_)

   * **IPv6 CIDR matching:** Technically supported since 1.0.2, officially supported
     since 1.1.0. (`PR 4004 <https://github.com/cilium/cilium/pull/4004>`_)

   Any rules that are not compatible with 1.0.x must be removed before
   downgrade.

#. Add or update the option ``clean-cilium-bpf-state`` to the `ConfigMap` and
   set to ``true``. This will cause BPF maps to be removed during the
   downgrade, which avoids bugs such as `Issue 5070
   <https://github.com/cilium/cilium/issues/5070>`_. As a side effect, any
   loadbalancing decisions for active connections will be disrupted during
   downgrade. For more information on changing `ConfigMap` options, see
   :ref:`upgrade_configmap`.

#. Follow the instructions in the section :ref:`upgrade_minor` to perform the
   downgrade to the latest micro release of the 1.0 series.

#. Set the ``clean-cilium-bpf-state`` `ConfigMap` option back to ``false``.

.. _upgrade_advanced:

Advanced
========

Upgrade Impact
--------------

Upgrades are designed to have minimal impact on your running deployment.
Networking connectivity, policy enforcement and load balancing will remain
functional in general. The following is a list of operations that will not be
available during the upgrade:

* API aware policy rules are enforced in user space proxies and are currently
  running as part of the Cilium pod unless Cilium is configured to run in Istio
  mode. Upgrading Cilium will cause the proxy to restart which will result in
  a connectivity outage and connection to be reset.

* Existing policy will remain effective but implementation of new policy rules
  will be postponed to after the upgrade has been completed on a particular
  node.

* Monitoring components such as ``cilium monitor`` will experience a brief
  outage while the Cilium pod is restarting. Events are queued up and read
  after the upgrade. If the number of events exceeds the event buffer size,
  events will be lost.

.. _upgrade_configmap:

Upgrading a ConfigMap
---------------------

This section describes the procedure to upgrade an existing `ConfigMap` to the
template of another version. 

Export the current ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

        $ kubectl get configmap -n kube-system cilium-config -o yaml --export > cilium-cm-old.yaml
        $ cat ./cilium-cm-old.yaml
        apiVersion: v1
        data:
          clean-cilium-state: "false"
          debug: "true"
          disable-ipv4: "false"
          etcd-config: |-
            ---
            endpoints:
            - https://192.168.33.11:2379
            #
            # In case you want to use TLS in etcd, uncomment the 'ca-file' line
            # and create a kubernetes secret by following the tutorial in
            # https://cilium.link/etcd-config
            ca-file: '/var/lib/etcd-secrets/etcd-ca'
            #
            # In case you want client to server authentication, uncomment the following
            # lines and add the certificate and key in cilium-etcd-secrets below
            key-file: '/var/lib/etcd-secrets/etcd-client-key'
            cert-file: '/var/lib/etcd-secrets/etcd-client-crt'
        kind: ConfigMap
        metadata:
          creationTimestamp: null
          name: cilium-config
          selfLink: /api/v1/namespaces/kube-system/configmaps/cilium-config


In the `ConfigMap` above, we can verify that Cilium is using ``debug`` with
``true``, it has a etcd endpoint running with `TLS <https://coreos.com/etcd/docs/latest/op-guide/security.html>`_,
and the etcd is set up to have `client to server authentication <https://coreos.com/etcd/docs/latest/op-guide/security.html#example-2-client-to-server-authentication-with-https-client-certificates>`_.

Download the ConfigMap with the changes for |SCM_BRANCH|
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. tabs::
  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-cm.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-cm.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-cm.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-cm.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-cm.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-cm.yaml

Verify its contents:

.. literalinclude:: ../../examples/kubernetes/1.8/cilium-cm.yaml

Add new options
~~~~~~~~~~~~~~~

Add the new options manually to your old `ConfigMap`, and make the necessary
changes.

In this example, the ``debug`` option is meant to be kept with ``true``, the
``etcd-config`` is kept unchanged, and ``legacy-host-allows-world`` is a new
option, but after reading the :ref:`version_notes` the value was kept unchanged
from the default value.

After making the necessary changes, the old `ConfigMap` was migrated with the
new options while keeping the configuration that we wanted:

::

        $ cat ./cilium-cm-old.yaml
        apiVersion: v1
        data:
          debug: "true"
          disable-ipv4: "false"
          # If you want to clean cilium state; change this value to true
          clean-cilium-state: "false"
          legacy-host-allows-world: "false"
          etcd-config: |-
            ---
            endpoints:
            - https://192.168.33.11:2379
            #
            # In case you want to use TLS in etcd, uncomment the 'ca-file' line
            # and create a kubernetes secret by following the tutorial in
            # https://cilium.link/etcd-config
            ca-file: '/var/lib/etcd-secrets/etcd-ca'
            #
            # In case you want client to server authentication, uncomment the following
            # lines and add the certificate and key in cilium-etcd-secrets below
            key-file: '/var/lib/etcd-secrets/etcd-client-key'
            cert-file: '/var/lib/etcd-secrets/etcd-client-crt'
        kind: ConfigMap
        metadata:
          creationTimestamp: null
          name: cilium-config
          selfLink: /api/v1/namespaces/kube-system/configmaps/cilium-config

Apply new ConfigMap
~~~~~~~~~~~~~~~~~~~

After adding the options, manually save the file with your changes and install
the `ConfigMap` in the ``kube-system`` namespace of your cluster.

::

        $ kubectl apply -n kube-system -f ./cilium-cm-old.yaml

As the `ConfigMap` is successfully upgraded we can start upgrading Cilium
``DaemonSet`` and ``RBAC`` which will pick up the latest configuration from the
`ConfigMap`.


.. _cidr_limitations:

Restrictions on unique prefix lengths for CIDR policy rules
-----------------------------------------------------------

The Linux kernel applies limitations on the complexity of BPF code that is
loaded into the kernel so that the code may be verified as safe to execute on
packets. Over time, Linux releases become more intelligent about the
verification of programs which allows more complex programs to be loaded.
However, the complexity limitations affect some features in Cilium depending
on the kernel version that is used with Cilium.

One such limitation affects Cilium's configuration of CIDR policies. On Linux
kernels 4.10 and earlier, this manifests as a restriction on the number of
unique prefix lengths supported in CIDR policy rules.

Unique prefix lengths are counted by looking at the prefix portion of CIDR
rules and considering which prefix lengths are unique. For example, in the
following policy example, the ``toCIDR`` section specifies a ``/32``, and the
``toCIDRSet`` section specifies a ``/8`` with a ``/12`` removed from it. In
addition, three prefix lengths are always counted: the host prefix length for
the protocol (IPv4: ``/32``, IPv6: ``/128``), the default prefix length
(``/0``), and the cluster prefix length (default IPv4: ``/8``, IPv6: ``/64``).
All in all, the following example counts as seven unique prefix lengths in IPv4:

* ``/32`` (from ``toCIDR``, also from host prefix)
* ``/12`` (from ``toCIDRSet``)
* ``/11`` (from ``toCIDRSet``)
* ``/10`` (from ``toCIDRSet``)
* ``o9`` (from ``toCIDRSet``)
* ``/8`` (from cluster prefix)
* ``/0`` (from default prefix)

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.json

Affected versions
~~~~~~~~~~~~~~~~~

* Any version of Cilium running on Linux 4.10 or earlier

When a CIDR policy with too many unique prefix lengths is imported, Cilium will
reject the policy with a message like the following:

.. tabs::
  .. group-tab:: Cilium 1.0

    .. code-block:: shell-session

     $ cilium policy import too_many_cidrs.json
     Error: Cannot import policy: [PUT /policy][500] putPolicyFailure  too many
     egress CIDR prefix lengths (128/40)

  .. group-tab:: Cilium 1.1 or later

     .. code-block:: shell-session

        $ cilium policy import too_many_cidrs.json
        Error: Cannot import policy: [PUT /policy][500] putPolicyFailure  Adding
        specified prefixes would result in too many prefix lengths (current: 3,
        result: 32, max: 18)

The supported count of unique prefix lengths may differ between Cilium minor
releases, for example Cilium 1.1 supports 20 unique prefix lengths on Linux
4.10 or older, while Cilium 1.2 only supports 18 (for IPv4) or 4 (for IPv6).

Mitigation
~~~~~~~~~~

Users may construct CIDR policies that use fewer unique prefix lengths. This
can be achieved by composing or decomposing adjacent prefixes.

Solution
~~~~~~~~

Upgrade the host Linux version to 4.11 or later. This step is beyond the scope
of the Cilium guide.


.. _host_vs_world:

Traffic from world to endpoints is classified as from host
----------------------------------------------------------

In Cilium 1.0, all traffic from the host, including from local processes and
traffic that is masqueraded from the outside world to the host IP, would be
classified as from the ``host`` entity (``reserved:host`` label).
Furthermore, to allow Kubernetes agents to perform health checks over IP into
the endpoints, the host is allowed by default. This means that all traffic from
the outside world is also allowed by default, regardless of security policy.

Affected versions
~~~~~~~~~~~~~~~~~

* Cilium 1.0 or earlier deployed using the DaemonSet and ConfigMap YAMLs
  provided with that release, or
* Later versions of Cilium deployed using the YAMLs provided with Cilium 1.0 or
  earlier.

Affected environments will see no output for one or more of the below commands:

.. code-block:: shell-session

  $ kubectl get ds cilium -n kube-system -o yaml | grep -B 3 -A 2 -i legacy-host-allows-world
  $ kubectl get cm cilium-config -n kube-system -o yaml | grep -i legacy-host-allows-world

Unaffected environments will see the following output (note the configMapKeyRef key in the Cilium DaemonSet and the ``legacy-host-allows-world: "false"`` setting of the ConfigMap):

.. code-block:: shell-session

  $ kubectl get ds cilium -n kube-system -o yaml | grep -B 3 -A 2 -i legacy-host-allows-world
            - name: CILIUM_LEGACY_HOST_ALLOWS_WORLD
              valueFrom:
                configMapKeyRef:
                  name: cilium-config
                  optional: true
                  key: legacy-host-allows-world
  $ kubectl get cm cilium-config -n kube-system -o yaml | grep -i legacy-host-allows-world
    legacy-host-allows-world: "false"

Mitigation
~~~~~~~~~~

Users who are not reliant upon IP-based health checks for their kubernetes pods
may mitigate this issue on earlier versions of Cilium by adding the argument
``--allow-localhost=policy`` to the Cilium DaemonSet for the Cilium container.
This prevents the automatic insertion of L3 allow policy in kubernetes
environments. Note however that with this option, if the Cilium Network Policy
allows traffic from the host, then it will still allow access from the outside
world.

.. code-block:: shell-session

  $ kubectl edit ds cilium -n kube-system
  (Edit the "args" section to add the option "--allow-localhost=policy")
  $ kubectl rollout status daemonset/cilium -n kube-system
  (Wait for kubernetes to redeploy Cilium with the new options)

Solution
~~~~~~~~

Cilium 1.1 and later only classify traffic from a process on the local host as
from the ``host`` entity; other traffic that is masqueraded to the host IP is
now classified as from the ``world`` entity (``reserved:world`` label).
Fresh deployments using the Cilium 1.1 YAMLs are not affected.

Affected users are recommended to upgrade using the steps below.

Upgrade steps
~~~~~~~~~~~~~

#. Redeploy the Cilium DaemonSet with the YAMLs provided with the Cilium 1.1 or
   later release. The instructions for this are found at the top of the
   :ref:`admin_upgrade`.

#. Add the config option ``legacy-host-allows-world: "false"`` to the Cilium
   ConfigMap under the "data" paragraph.

     .. code-block:: shell-session

       $ kubectl edit configmap cilium-config -n kube-system
       (Add a new line with the config option above in the "data" paragraph)

#. (Optional) Update the Cilium Network Policies to allow specific traffic from
   the outside world. For more information, see :ref:`network_policy`.

