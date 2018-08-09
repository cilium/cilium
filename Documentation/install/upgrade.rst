.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_upgrade:

*************
Upgrade Guide
*************

Kubernetes Cilium Upgrade
=========================

This Cilium Kubernetes upgrade guide is divided into two sections:

* **General Upgrade Workflow**: Provides a conceptual understanding of how
  Cilium upgrade works in Kubernetes.

* **Specific Upgrade Instructions**: Details considerations and instructions
  for specific upgrades between recent Cilium versions.

.. _upgrade_general:

General Upgrade Workflow
~~~~~~~~~~~~~~~~~~~~~~~~

The configuration of a standard Cilium Kubernetes deployment consists of
several Kubernetes resources:

* A ``DaemonSet`` resource:  describes the Cilium pod that is deployed to each
  Kubernetes node.  This pod runs the cilium-agent and associated daemons. The
  configuration of this DaemonSet includes the image tag indicating the exact
  version of the Cilium docker container (e.g., v1.0.0) and command-line
  options passed to the cilium-agent.

* A ``ConfigMap`` resource:  describes common configuration values that are
  passed to the cilium-agent, such as the kvstore endpoint and credentials,
  enabling/disabling debug mode, etc.

* ``ServiceAccount``, ``ClusterRole``, and ``ClusterRoleBindings`` resources:
  the identity and permissions used by cilium-agent to access the Kubernetes
  API server when Kubernetes RBAC is enabled.

* A ``Secret`` resource: describes the credentials use access the etcd kvstore,
  if required.

If you have followed the installation guide from :ref:`ds_deploy`, all of the
above resources were installed via a single ``cilium.yaml`` file.

All upgrades require at least updating the ``DaemonSet`` to point to the newer
Cilium image tag. However, *safely* upgrading Cilium may also required changes
additional changes to the ``DaemonSet``, ``ConfigMap`` or ``RBAC`` related
resources. This depends on your current and target Cilium versions, so it is
critical to read the :ref:`specific_upgrade` below referring to your target
Cilium version.

In general, the easiest way to ensure you are making all required updates to
Cilium related resources is to download new versions of those resources, and
apply them to your Kubernetes environment.  The recommended high-level workflow
is:

#. Download a new ``cilium-cm.yaml`` file associated with your target version
   of Cilium, manually edit the file with any configuration options specific to
   your environment, and then apply the file to your cluster using kubectl.

#. Update the ``ServiceAccount``, ``ClusterRole``, and ``ClusterRoleBindings``
   resources by using kubectl to apply a new ``cilium-rbac.yaml`` associated
   with your target version of Cilium.

#. Update the ``DaemonSet`` resource by applying the ``cilium-ds.yaml``
   associated with your target version of Cilium.

If there are no changes required to the resources between two Cilium versions
(e.g., between two patch releases in the same minor version), then it is
possible to upgrade Cilium simply by editing the cilium image tag in the
DaemonSet. However, this short-cut should only be done if the
:ref:`specific_upgrade` instructions below confirm that it is safe.

When upgrading from one minor release to another minor release, for example
1.x to 1.y, it is generally safer to upgrade first to the latest release in the
1.x.z series, then subsequently upgrade to 1.y. This way, if there is any
unexpected issue during the upgrade, it can be safely rolled back to the latest
good version.

Below we will show examples of how Cilium should be upgraded using Kubernetes
rolling upgrade functionality in order to preserve any existing Cilium
configuration changes (e.g., etc configuration) and minimize network
disruptions for running workloads. These instructions upgrade Cilium to version
"\ |SCM_BRANCH|" by updating the ``ConfigMap``, ``RBAC`` rules and
``DaemonSet`` files separately. Rather than installing all configuration in one
``cilium.yaml`` file, which could override any custom ``ConfigMap``
configuration, installing these files separately allows upgrade to be staged
and for user configuration to not be affected by the upgrade.

.. _upgrade_cm:

Upgrade ConfigMap (Recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Upgrading the `ConfigMap` should be done manually before upgrading the ``RBAC``
and the ``DaemonSet``. Upgrading the `ConfigMap` first will not affect current
Cilium pods as the new `ConfigMap` configurations are only used when a pod is
restarted.

1. To update your current `ConfigMap` store it locally so you can modify it:

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

2. Download the `ConfigMap` with the changes for "\ |SCM_BRANCH|":

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


Verify its contents:

.. literalinclude:: ../../examples/kubernetes/1.8/cilium-cm.yaml


3. Add the new options manually to your old `ConfigMap`, and make the necessary
changes.

In this example, the ``debug`` option is meant to be kept with ``true``, the
``etcd-config`` is kept unchanged, and ``legacy-host-allows-world`` is a new
option, but after reading the :ref:`upgrade_notes` the value was kept unchanged
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

After adding the options, manually save the file with your changes and install
the `ConfigMap` in the ``kube-system`` namespace of your cluster.

::

        $ kubectl apply -n kube-system -f ./cilium-cm-old.yaml

As the `ConfigMap` is successfully upgraded we can start upgrading Cilium
``DaemonSet`` and ``RBAC`` which will pick up the latest configuration from the
`ConfigMap`.

Upgrade Cilium DaemonSet and RBAC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are two methods to upgrade the Cilium `DaemonSet`:

* Full upgrade of the ``RBAC`` and ``DaemonSet`` resources: This is the safest
  option, which pulls in the latest configuration options for the Cilium
  daemon. If in doubt, use this approach.

* Set the version in the existing ``DaemonSet``: A simpler upgrade procedure
  which does not update the Daemon options.

Refer to the section :ref:`specific_upgrade` for more details on which approach
is relevant for the target Cilium version.

The following sections describe how to upgrade using either of the above
approaches, then how to monitor (and if necessary, roll back) the upgrade
process.

.. _upgrade_ds:

Full Upgrade of RBAC and DaemonSet
""""""""""""""""""""""""""""""""""

Simply pick your Kubernetes version and run ``kubectl apply`` for the ``RBAC``
and the ``DaemonSet``.

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

.. _upgrade_version:

Direct version upgrade
""""""""""""""""""""""

.. note::

    Direct version upgrade is not recommended for major or minor version
    upgrades. Upgrade using the :ref:`upgrade_ds` instructions instead.

You can alternatively substitute the version ``vX.Y.Z`` for the desired Cilium
version number in the command below, but be aware that copy of the spec file
stored in Kubernetes might run out-of-sync with the CLI flags, or options,
specified by each Cilium version.

.. code-block:: shell-session

    $ kubectl set image daemonset/cilium -n kube-system cilium-agent=docker.io/cilium/cilium:vX.Y.Z

Monitor the upgrade procedure
"""""""""""""""""""""""""""""

To monitor the rollout and confirm it is complete, run:

.. code-block:: shell-session

    $ kubectl rollout status daemonset/cilium -n kube-system

During the upgrade roll-out, Cilium will typically continue to forward traffic
at L3/L4, and all endpoints and their configuration will be preserved across
the upgrade. However, because the L7 proxies implementing HTTP, gRPC, and
Kafka-aware filtering currently reside in the same Pod as Cilium, they are
removed and re-installed as part of the rollout. As a result, any proxied
connections will be lost and clients must reconnect.

Rolling back the upgrade (Typically unnecessary)
""""""""""""""""""""""""""""""""""""""""""""""""

Occasionally, it may be necessary to undo the rollout because a step was missed
or something went wrong during upgrade. To undo the rollout via rollback, run:

.. code-block:: shell-session

    $ kubectl rollout undo daemonset/cilium -n kube-system

This will revert the latest changes to the Cilium ``DaemonSet`` and return
Cilium to the state it was in prior to the upgrade.

.. _specific_upgrade:

Specific Upgrade Instructions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
| ``1.0.x``             | ``1.0.y``             | Not required          | N/A                     | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.0.x``             | ``1.1.y``             | Required              | N/A                     | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.1.x``             | ``1.1.y``             | Not required          | N/A                     | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.1.x``, ``x >= 3`` | ``1.2.y``             | Required              | Temporary disruption[2] | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

#. **Temporary disruption**: All traffic may be temporarily disrupted during
   upgrade. Connections should successfully re-establish without requiring
   clients to reconnect.

.. include:: upgrade-1.2.rst

.. include:: upgrade-1.1.rst

.. include:: upgrade-1.0.rst

Downgrade
~~~~~~~~~

Occasionally, when encountering issues with a particular version of Cilium, it
may be useful to alternatively downgrade an instance or deployment. The above
instructions may be used, replacing the "\ |SCM_BRANCH|" version with the
desired version.

Particular versions of Cilium may introduce new features, however, so if Cilium
is configured with the newer feature, and a downgrade is performed, then the
downgrade may leave Cilium in a bad state. Below is a table of features which
have been introduced in later versions of Cilium. If you are using a feature
in the below table, then a downgrade cannot be safely implemented unless you
also disable the usage of the feature.

+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+
| Feature                                      | Minimum version   | Mitigation                                   | Feature Link                                              |
+==============================================+===================+==============================================+===========================================================+
| CIDR policies matching on IPv6 prefix ranges | ``v1.0.2``        | Remove policies that contain IPv6 CIDR rules | `PR 4004 <https://github.com/cilium/cilium/pull/4004>`_   |
+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+
| CIDR policies matching on default prefix     | ``v1.1.0``        | Remove policies that match a ``/0`` prefix   | `PR 4458 <https://github.com/cilium/cilium/pull/4458>`_   |
+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+
| CIDR-dependent L4 policies                   | ``v1.1.0``        | Remove rules with both ``toPorts`` and       | `PR 3835 <https://github.com/cilium/cilium/pull/3835>`_   |
|                                              |                   | ``toCIDR`` from policy                       |                                                           |
+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+
| Monitor Aggregation                          | ``v1.2.0``        | Re-install ``DaemonSet`` from target version | `PR 5118 <https://github.com/cilium/cilium/pull/5118>`_   |
+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+

.. _upgrade_notes:

Upgrade notes
=============

This section describes known issues and limitations with released versions of
Cilium which may require user interaction to mitigate or remediate.

.. _cidr_limitations:

Restrictions on unique prefix lengths for CIDR policy rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
* ``/9`` (from ``toCIDRSet``)
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
^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^

Users may construct CIDR policies that use fewer unique prefix lengths. This
can be achieved by composing or decomposing adjacent prefixes.

Solution
^^^^^^^^

Upgrade the host Linux version to 4.11 or later. This step is beyond the scope
of the Cilium guide.


.. _host_vs_world:

Traffic from world to endpoints is classified as from host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In Cilium 1.0, all traffic from the host, including from local processes and
traffic that is masqueraded from the outside world to the host IP, would be
classified as from the ``host`` entity (``reserved:host`` label).
Furthermore, to allow Kubernetes agents to perform health checks over IP into
the endpoints, the host is allowed by default. This means that all traffic from
the outside world is also allowed by default, regardless of security policy.

Affected versions
^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^

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
^^^^^^^^

Cilium 1.1 and later only classify traffic from a process on the local host as
from the ``host`` entity; other traffic that is masqueraded to the host IP is
now classified as from the ``world`` entity (``reserved:world`` label).
Fresh deployments using the Cilium 1.1 YAMLs are not affected.

Affected users are recommended to upgrade using the steps below.

Upgrade steps
^^^^^^^^^^^^^

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
