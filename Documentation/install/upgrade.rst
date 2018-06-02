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

+----------------------------------------------+-------------------+-------------------------------------------------------------------------------+-----------------------------------------------------------+
| Feature                                      | Minimum version   | Mitigation                                                                    | Feature Link                                              |
+==============================================+===================+===============================================================================+===========================================================+
| CIDR policies matching on IPv6 prefix ranges | ``v1.0.2``        | Remove policies that contain IPv6 CIDR rules                                  | `Github PR <https://github.com/cilium/cilium/pull/4004>`_ |
+----------------------------------------------+-------------------+-------------------------------------------------------------------------------+-----------------------------------------------------------+
| Using default MTU of 1500 bytes              | ``v1.1.0``        | Re-deploy endpoints that use an MTU different from ``cilium_host`` device MTU | `Github PR <https://github.com/cilium/cilium/pull/4323>`_ |
+----------------------------------------------+-------------------+-------------------------------------------------------------------------------+-----------------------------------------------------------+

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
dropped. Cilium 1.1 by default on a fresh deployment will configure the MTU to
1500 bytes instead to remediate this issue.

If Cilium is upgraded from 1.0 to 1.1 or later then the old MTU is retained by
default. This ensures that existing pod connectivity is unaffected during
upgrade, but will not provide remediation for issue described above. To convert
over to the new behavior is a two step process:

* Redeploy Cilium with the command-line parameter ``--autodetect-mtu=false``.
  For kubernetes deployments, the easiest way to do this is to edit the
  ``cilium-config`` ConfigMap and set the ``autodetect-mtu`` option to
  ``false``, then delete the Cilium pods.

.. code-block:: shell-session

    $ kubectl edit configmap cilium-config -n kube-system
    (Update autodetect-mtu configuration option)
    $ kubectl delete pod -n kube-system $(kubectl get pods -n kube-system -o json | jq -r '.items | map(select(.metadata.generateName=="cilium-"))[] | .metadata.name')
    pod "cilium-5snsq" deleted
    pod "cilium-q48t9" deleted
    $ kubectl rollout status daemonset/cilium -n kube-system
    Waiting for rollout to finish: 0 of 2 updated pods are available...
    Waiting for rollout to finish: 1 out of 2 new pods have been updated...
    Waiting for rollout to finish: 0 of 2 updated pods are available...
    Waiting for rollout to finish: 1 of 2 updated pods are available...
    daemon set "cilium" successfully rolled out

* When the new version of Cilium has been deployed, redeploy all endpoints that
  were created with the previous version of Cilium. This step varies depending
  on the way the applications were deployed. To fetch a list of pods that must
  be redeployed, fetch the list of cilium endpoints excluding ``cilium-health``:

.. code-block:: shell-session

  $ kubectl get cep --all-namespaces -o wide | grep -v "cilium-health"

To determine that the new behavior is in place, from the node:

.. code-block:: shell-session

  $ ip link show | grep -e '^.* cilium' -e '^.* lxc' | sed 's/.*\(mtu [0-9]*\).*/\1/g' | sort | uniq
  mtu 1500

The presence of a single output entry stating ``mtu 1500`` in the above output
shows that all pods and Cilium devices are using MTU 1500.
