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

Cilium should be upgraded using Kubernetes rolling upgrade functionality in
order to minimize network disruptions for running workloads.

If you have followed the installation guide from :ref:`ds_deploy`, you probably
have deployed a single ``cilium.yaml`` file. That file contains all the
necessary components to run Cilium in your Kubernetes cluster. Those components
were a `ConfigMap`, a ``ServiceAccount``, a ``DaemonSet``, and the ``RBAC`` for
Cilium to access the Kubernetes api-server.

Since Cilium might need more, or fewer permissions to access Kubernetes
api-server between releases, the ``RBAC`` might change between versions as well.

The safest way to upgrade Cilium to version "\ |SCM_BRANCH|" is by updating the
``RBAC`` rules and the ``DaemonSet`` files separately, which makes sure the
`ConfigMap` initially set up by ``cilium.yaml`` and already stored in Kubernetes
will not be affected by the upgrade.

It is also recommended to upgrade the `ConfigMap`, but this is a process that
should be done manually before upgrading the ``RBAC`` and the ``DaemonSet``.
Upgrading the `ConfigMap` first will not affect current Cilium pods as the
new `ConfigMap` configurations are only used when a pod is restarted.

Upgrade ConfigMap
~~~~~~~~~~~~~~~~~

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
  .. group-tab:: K8s 1.7

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.7/cilium-cm.yaml

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

.. literalinclude:: ../../examples/kubernetes/1.7/cilium-cm.yaml


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

Upgrading Cilium DaemonSet and RBAC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Simply pick your Kubernetes version and run ``kubectl apply`` for the ``RBAC``
and the ``DaemonSet``.

Both files are dedicated to "\ |SCM_BRANCH|" for each Kubernetes version.

.. tabs::
  .. group-tab:: K8s 1.7

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.7/cilium-rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.7/cilium-ds.yaml

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


You can also substitute the desired Cilium version number for vX.Y.Z in the
command below, but be aware that copy of the spec file stored in Kubernetes
might run out-of-sync with the CLI flags, or options, specified by each Cilium
version.

::

    kubectl set image daemonset/cilium -n kube-system cilium-agent=docker.io/cilium/cilium:vX.Y.Z

To monitor the rollout and confirm it is complete, run:

::

    kubectl rollout status daemonset/cilium -n kube-system

To undo the rollout via rollback, run:

::

    kubectl rollout undo daemonset/cilium -n kube-system

Cilium will continue to forward traffic at L3/L4 during the roll-out, and all endpoints and their configuration will be preserved across
the upgrade rollout.   However, because the L7 proxies implementing HTTP, gRPC, and Kafka-aware filtering currently reside in the
same Pod as Cilium, they are removed and re-installed as part of the rollout.   As a result, any proxied connections will be lost and
clients must reconnect.

Downgrade
=========

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
| CIDR policies matching on IPv6 prefix ranges | ``v1.0.2``        | Remove policies that contain IPv6 CIDR rules | `Github PR <https://github.com/cilium/cilium/pull/4004>`_ |
+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+
+ CIDR policies matching on default prefix     | ``v1.1.0``        | Remove policies that match a ``/0`` prefix   | `Github PR <https://github.com/cilium/cilium/pull/4458>`_ |
+----------------------------------------------+-------------------+----------------------------------------------+-----------------------------------------------------------+

.. _upgrade_notes:

Upgrade notes
=============

The below issues have been fixed in Cilium 1.1, but require user interaction to
mitigate or remediate the issue for users upgrading from an earlier release.

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
