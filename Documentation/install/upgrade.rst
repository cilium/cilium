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

Upgrade notes
=============

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

Cilium 1.1 fixes the above issue by increasing the MTU of the Cilium-related
devices and endpoint devices to 1500B (or larger based on container runtime
settings), then configuring a route within the endpoint at a lower MTU to
ensure that transmitted packets will fit within tunnel encapsulation. This
addresses the above issue for all new pods.

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
