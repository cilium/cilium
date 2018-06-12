.. _admin_upgrade:

*************
Upgrade Guide
*************

Kubernetes Cilium Upgrade
=========================

Cilium should be upgraded using Kubernetes rolling upgrade functionality in order to minimize network disruptions for running workloads.

The safest way to upgrade Cilium to version "\ |SCM_BRANCH|" is by updating the
RBAC rules and the DaemonSet file provided, which makes sure the ConfigMap,
initially set up by ``cilium.yaml``, already stored in the cluster will not be
affected by the upgrade.
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

Upgrade notes
=============

The below issues have been fixed in Cilium 1.1, but require user interaction to
mitigate or remediate the issue for users upgrading from an earlier release.

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

.. _err_low_mtu:

MTU handling behavior change in Cilium 1.1
------------------------------------------

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
~~~~~~~~~~~~~~~~~

* Cilium 1.0 or earlier.

Cilium 1.1 and later are not affected.

Mitigation
~~~~~~~~~~

There is no known mitigation for users running Cilium 1.0 at this time.

Solution
~~~~~~~~

Cilium 1.1 fixes the above issue by increasing the MTU of the Cilium-related
devices and endpoint devices to 1500B (or larger based on container runtime
settings), then configuring a route within the endpoint at a lower MTU to
ensure that transmitted packets will fit within tunnel encapsulation. This
addresses the above issue for all new pods.

Endpoints that were deployed on Cilium 1.0 must be redeployed to remediate this
issue.

Upgrade Steps
~~~~~~~~~~~~~

When upgrading from Cilium 1.0 to 1.1 or later, existing pods will not
automatically inherit these new settings. To apply the new MTU settings to
existing endpoints, they must be re-deployed. To fetch a list of affected pods
in kubernetes environments, run the following command:

.. code-block:: shell-session

  $ kubectl get cep --all-namespaces
  NAMESPACE     NAME                         AGE
  default       deathstar-765fd545f9-m6bpt   50m
  default       deathstar-765fd545f9-vlfth   50m
  default       tiefighter                   50m
  default       xwing                        50m
  kube-system   cilium-health-k8s1           27s
  kube-system   cilium-health-k8s2           25s
  kube-system   kube-dns-59d8c5f9b5-g2pnt    2h

The ``cilium-health`` endpoints do not need to be redeployed, as Cilium will
redeploy them automatically upon upgrade. Depending on how the endpoints were
originally deployed, this may be as simple as running
``kubectl delete pod <podname>``. Once each pod has been redeployed, you can
fetch a list of the related interfaces and confirm that the new MTU settings
have been applied via the following commands:

.. code-block:: shell-session

  $ kubectl get cep --all-namespaces -o yaml | grep -e "pod-name:" -e "interface-name"
        pod-name: default:deathstar-765fd545f9-m6bpt
        interface-name: lxc55330
        pod-name: default:deathstar-765fd545f9-vlfth
        interface-name: lxc4fe9b
        pod-name: default:tiefighter
        interface-name: lxcf1e94
        pod-name: default:xwing
        interface-name: lxc7cb0f
        pod-name: ':'
        interface-name: cilium_health
        pod-name: ':'
        interface-name: cilium_health
        pod-name: kube-system:kube-dns-59d8c5f9b5-g2pnt
        interface-name: lxc0e2f6
  $ ip link show lxc0e2f6 | grep mtu
  22: lxc0e2f6@if21: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default

The first command above lists all Cilium endpoints and their corresponding
interface names, and the second command demonstrates how to find the MTU for
the interface. Typically the MTU should be 1500 bytes after the endpoints have
been re-deployed, unless the Cilium CNI configuration requests a different MTU.
