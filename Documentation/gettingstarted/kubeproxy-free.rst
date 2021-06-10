.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _kubeproxy-free:

*****************************
Kubernetes Without kube-proxy
*****************************

This guide explains how to provision a Kubernetes cluster without ``kube-proxy``,
and to use Cilium to fully replace it. For simplicity, we will use ``kubeadm`` to
bootstrap the cluster.

For installing ``kubeadm`` and for more provisioning options please refer to
`the official kubeadm documentation <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/>`_.

.. note::

   Cilium's kube-proxy replacement depends on the :ref:`host-services` feature,
   therefore a v4.19.57, v5.1.16, v5.2.0 or more recent Linux kernel is required.
   Linux kernels v5.3 and v5.8 add additional features that Cilium can use to
   further optimize the kube-proxy replacement implementation.

   Note that v5.0.y kernels do not have the fix required to run the kube-proxy
   replacement since at this point in time the v5.0.y stable kernel is end-of-life
   (EOL) and not maintained anymore on kernel.org. For individual distribution
   maintained kernels, the situation could differ. Therefore, please check with
   your distribution.

Quick-Start
###########

Initialize the control-plane node via ``kubeadm init`` and skip the
installation of the ``kube-proxy`` add-on:

.. code-block:: shell-session

    $ kubeadm init --skip-phases=addon/kube-proxy

Afterwards, join worker nodes by specifying the control-plane node IP address and
the token returned by ``kubeadm init``:

.. code-block:: shell-session

    $ kubeadm join <..>

.. note::

    Please ensure that
    `kubelet <https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/>`_'s
    ``--node-ip`` is set correctly on each worker if you have multiple interfaces.
    Cilium's kube-proxy replacement may not work correctly otherwise.
    You can validate this by running ``kubectl get nodes -o wide`` to see whether
    each node has an ``InternalIP`` which is assigned to a device with the same
    name on each node.

For existing installations with ``kube-proxy`` running as a DaemonSet, remove it
by using the following commands below. **Careful:** Be aware that this will break
existing service connections. It will also stop service related traffic until the
Cilium replacement has been installed:

.. code-block:: shell-session

    $ kubectl -n kube-system delete ds kube-proxy
    $ # Delete the configmap as well to avoid kube-proxy being reinstalled during a kubeadm upgrade (works only for K8s 1.19 and newer)
    $ kubectl -n kube-system delete cm kube-proxy
    $ # Run on each node:
    $ iptables-restore <(iptables-save | grep -v KUBE)

.. include:: k8s-install-download-release.rst

Next, generate the required YAML files and deploy them. **Important:** Replace
``REPLACE_WITH_API_SERVER_IP`` and ``REPLACE_WITH_API_SERVER_PORT`` below with the concrete
control-plane node IP address and the kube-apiserver port number reported by ``kubeadm init``
(usually, it is port ``6443``).

Specifying this is necessary as ``kubeadm init`` is run explicitly without setting
up kube-proxy and as a consequence, although it exports ``KUBERNETES_SERVICE_HOST``
and ``KUBERNETES_SERVICE_PORT`` with a ClusterIP of the kube-apiserver service
to the environment, there is no kube-proxy in our setup provisioning that service.
The Cilium agent therefore needs to be made aware of this information through below
configuration.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=strict \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

.. note::

    Cilium will automatically mount cgroup v2 filesystem required to attach BPF
    cgroup programs by default at the path ``/run/cilium/cgroupv2``. In order to
    do that, it needs to mount the host ``/proc`` inside an init container
    launched by the daemonset temporarily. If you need to disable the auto-mount,
    specify ``--set cgroup.autoMount.enabled=false``, and set the host mount point
    where cgroup v2 filesystem is already mounted by using ``--set cgroup.hostRoot``.
    For example, if not already mounted, you can mount cgroup v2 filesystem by
    running the below command on the host, and specify ``--set cgroup.hostRoot=/sys/fs/cgroup``.

    .. code:: shell-session

        mount -t cgroup2 none /sys/fs/cgroup

This will install Cilium as a CNI plugin with the eBPF kube-proxy replacement to
implement handling of Kubernetes services of type ClusterIP, NodePort, LoadBalancer
and services with externalIPs. On top of that the eBPF kube-proxy replacement also
supports hostPort for containers such that using portmap is not necessary anymore.

Finally, as a last step, verify that Cilium has come up correctly on all nodes and
is ready to operate:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-fmh8d        1/1       Running   0          10m
    cilium-mkcmb        1/1       Running   0          10m

Note, in above Helm configuration, the ``kubeProxyReplacement`` has been set to
``strict`` mode. This means that the Cilium agent will bail out in case the
underlying Linux kernel support is missing.

By default, Helm sets ``kubeProxyReplacement=probe``, which automatically
disables a subset of the features to implement the kube-proxy replacement instead
of bailing out if the kernel support is missing. This makes the assumption that
Cilium's eBPF kube-proxy replacement would co-exist with kube-proxy on the system
to optimize Kubernetes services. Given we've used kubeadm to explicitly deploy
a kube-proxy-free setup, ``strict`` mode is explicitly set in this guide to ensure
that we do not rely on a (non-existing) fallback.

Cilium's eBPF kube-proxy replacement is supported in direct routing as well as in
tunneling mode.

Validate the Setup
##################

After deploying Cilium with above Quick-Start guide, we can first validate that
the Cilium agent is running in the desired mode:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-fmh8d -- cilium status | grep KubeProxyReplacement
    KubeProxyReplacement:   Strict	[eth0 (Direct Routing), eth1]

Use ``--verbose`` for full details:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-fmh8d -- cilium status --verbose
    [...]
    KubeProxyReplacement Details:
      Status:              Strict
      Protocols:           TCP, UDP
      Devices:             eth0 (Direct Routing), eth1
      Mode:                SNAT
      Backend Selection:   Random
      Session Affinity:    Enabled
      XDP Acceleration:    Disabled
      Services:
      - ClusterIP:      Enabled
      - NodePort:       Enabled (Range: 30000-32767)
      - LoadBalancer:   Enabled
      - externalIPs:    Enabled
      - HostPort:       Enabled
    [...]

As a optional next step, we deploy nginx pods, create a new NodePort service and
validate that Cilium installed the service correctly.

The following yaml is used for the backend pods:

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: my-nginx
    spec:
      selector:
        matchLabels:
          run: my-nginx
      replicas: 2
      template:
        metadata:
          labels:
            run: my-nginx
        spec:
          containers:
          - name: my-nginx
            image: nginx
            ports:
            - containerPort: 80

Verify that the nginx pods are up and running:

.. code-block:: shell-session

    $ kubectl get pods -l run=my-nginx -o wide
    NAME                        READY   STATUS    RESTARTS   AGE   IP             NODE   NOMINATED NODE   READINESS GATES
    my-nginx-756fb87568-gmp8c   1/1     Running   0          62m   10.217.0.149   apoc   <none>           <none>
    my-nginx-756fb87568-n5scv   1/1     Running   0          62m   10.217.0.107   apoc   <none>           <none>

In the next step, we create a NodePort service for the two instances:

.. code-block:: shell-session

    $ kubectl expose deployment my-nginx --type=NodePort --port=80
    service/my-nginx exposed

Verify that the NodePort service has been created:

.. code-block:: shell-session

    $ kubectl get svc my-nginx
    NAME       TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
    my-nginx   NodePort   10.104.239.135   <none>        80:31940/TCP   24m

With the help of the ``cilium service list`` command, we can validate that
Cilium's eBPF kube-proxy replacement created the new NodePort services under
port ``31940`` (one for each of devices ``eth0`` and ``eth1``):

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-fmh8d -- cilium service list
    ID   Frontend               Service Type   Backend
    [...]
    4    10.104.239.135:80      ClusterIP      1 => 10.217.0.107:80
                                               2 => 10.217.0.149:80
    5    0.0.0.0:31940          NodePort       1 => 10.217.0.107:80
                                               2 => 10.217.0.149:80
    6    192.168.178.29:31940   NodePort       1 => 10.217.0.107:80
                                               2 => 10.217.0.149:80
    7    172.16.0.29:31940      NodePort       1 => 10.217.0.107:80
                                               2 => 10.217.0.149:80

At the same time we can verify, using ``iptables`` in the host namespace,
that no ``iptables`` rule for the service is present:

.. code-block:: shell-session

    $ iptables-save | grep KUBE-SVC
    [ empty line ]

Last but not least, a simple ``curl`` test shows connectivity for the exposed
NodePort port ``31940`` as well as for the ClusterIP:

.. code-block:: shell-session

    $ curl 127.0.0.1:31940
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

.. code-block:: shell-session

    $ curl 192.168.178.29:31940
    <!doctype html>
    <html>
    <head>
    <title>welcome to nginx!</title>
    [....]

.. code-block:: shell-session

    $ curl 172.16.0.29:31940
    <!doctype html>
    <html>
    <head>
    <title>welcome to nginx!</title>
    [....]

.. code-block:: shell-session

    $ curl 10.104.239.135:80
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

As can be seen, Cilium's eBPF kube-proxy replacement is set up correctly.

Advanced Configuration
######################

This section covers a few advanced configuration modes for the kube-proxy replacement
that go beyond the above Quick-Start guide and are entirely optional.

Client Source IP Preservation
*****************************

Cilium's eBPF kube-proxy replacement implements a number of options in order to avoid
performing SNAT on NodePort requests where the client source IP address would otherwise
be lost on its path to the service endpoint.

- ``externalTrafficPolicy=Local``: The ``Local`` policy is generally supported through
  the eBPF implementation. In-cluster connectivity for services with ``externalTrafficPolicy=Local``
  is possible and can also be reached from nodes which have no local backends, meaning,
  given SNAT does not need to be performed, all service endpoints are available for
  load balancing from in-cluster side.

- ``externalTrafficPolicy=Cluster``: For the ``Cluster`` policy which is the default
  upon service creation, multiple options exist for achieving client source IP preservation
  for external traffic, that is, operating the kube-proxy replacement in :ref:`DSR<DSR Mode>`
  or :ref:`Hybrid<Hybrid Mode>` mode if only TCP-based services are exposed to the outside
  world for the latter.

Maglev Consistent Hashing (Beta)
********************************

Cilium's eBPF kube-proxy replacement supports consistent hashing by implementing a variant
of `The Maglev paper <https://storage.googleapis.com/pub-tools-public-publication-data/pdf/44824.pdf>`_
hashing in its load balancer for backend selection. This improves resiliency in case of
failures as well as better load balancing properties since nodes added to the cluster will
make the same, consistent backend selection throughout the cluster for a given 5-tuple without
having to synchronize state with the other nodes. Similarly, upon backend removal the backend
lookup tables are reprogrammed with minimal disruption for unrelated backends (at most 1%
difference in the reassignments) for the given service.

Maglev hashing for services load balancing can be enabled by setting ``loadBalancer.algorithm=maglev``:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=strict \\
        --set loadBalancer.algorithm=maglev \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

Note that Maglev hashing is applied only to external (N-S) traffic. For
in-cluster service connections (E-W), sockets are assigned to service backends
directly, e.g. at TCP connect time, without any intermediate hop and thus are
not subject to Maglev. Maglev hashing is also supported for Cilium's
:ref:`XDP<XDP Acceleration>` acceleration.

There are two more Maglev-specific configuration settings: ``maglev.tableSize``
and ``maglev.hashSeed``.

``maglev.tableSize`` specifies the size of the Maglev lookup table for each single service.
`Maglev <https://storage.googleapis.com/pub-tools-public-publication-data/pdf/44824.pdf>`_
recommends the table size (``M``) to be significantly larger than the number of maximum expected
backends (``N``). In practice that means that ``M`` should be larger than ``100 * N`` in
order to guarantee the property of at most 1% difference in the reassignments on backend
changes. ``M`` must be a prime number. Cilium uses a default size of ``16381`` for ``M``.
The following sizes for ``M`` are supported as ``maglev.tableSize`` Helm option:

+----------------------------+
| ``maglev.tableSize`` value |
+============================+
| 251                        |
+----------------------------+
| 509                        |
+----------------------------+
| 1021                       |
+----------------------------+
| 2039                       |
+----------------------------+
| 4093                       |
+----------------------------+
| 8191                       |
+----------------------------+
| 16381                      |
+----------------------------+
| 32749                      |
+----------------------------+
| 65521                      |
+----------------------------+
| 131071                     |
+----------------------------+

For example, a ``maglev.tableSize`` of ``16381`` is suitable for a maximum of ``~160`` backends
per service. If a higher number of backends are provisioned under this setting, then the
difference in reassignments on backend changes will increase.

The ``maglev.hashSeed`` option is recommended to be set in order for Cilium to not rely on the
fixed built-in seed. The seed is a base64-encoded 16 byte-random number, and can be
generated once through ``head -c12 /dev/urandom | base64 -w0``, for example. Every Cilium agent
in the cluster must use the same hash seed in order for Maglev to work.

The below deployment example is generating and passing such seed to Helm as well as setting the
Maglev table size to ``65521`` in order to allow for ``~650`` maximum number of backends for a
given service (with the property of at most 1% difference on backend reassignments):

.. parsed-literal::

    SEED=$(head -c16 /dev/urandom | base64 -w0)
    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=strict \\
        --set loadBalancer.algorithm=maglev \\
        --set maglev.tableSize=65521 \\
        --set maglev.hashSeed=$SEED \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

Note that enabling Maglev will have a higher memory consumption on each Cilium-managed node compared
to the default of ``loadBalancer.algorithm=random`` given ``random`` does not need the extra lookup
tables. However, ``random`` won't have consistent backend selection.

.. _DSR mode:

Direct Server Return (DSR)
**************************

By default, Cilium's eBPF NodePort implementation operates in SNAT mode. That is,
when node-external traffic arrives and the node determines that the backend for
the LoadBalancer, NodePort or services with externalIPs is at a remote node, then the
node is redirecting the request to the remote backend on its behalf by performing
SNAT. This does not require any additional MTU changes at the cost that replies
from the backend need to make the extra hop back that node in order to perform the
reverse SNAT translation there before returning the packet directly to the external
client.

This setting can be changed through the ``loadBalancer.mode`` Helm option to
``dsr`` in order to let Cilium's eBPF NodePort implementation operate in DSR mode.
In this mode, the backends reply directly to the external client without taking
the extra hop, meaning, backends reply by using the service IP/port as a source.
DSR currently requires Cilium to be deployed in :ref:`arch_direct_routing`, i.e.
it will not work in either tunneling mode.

Another advantage in DSR mode is that the client's source IP is preserved, so policy
can match on it at the backend node. In the SNAT mode this is not possible.
Given a specific backend can be used by multiple services, the backends need to be
made aware of the service IP/port which they need to reply with. Therefore, Cilium
encodes this information in a Cilium-specific IPv4 option or IPv6 Destination Option
extension header at the cost of advertising a lower MTU. For TCP services, Cilium
only encodes the service IP/port for the SYN packet, but not subsequent ones. The
latter also allows to operate Cilium in a hybrid mode as detailed in the next subsection
where DSR is used for TCP and SNAT for UDP in order to avoid an otherwise needed MTU
reduction.

Note that usage of DSR mode might not work in some public cloud provider environments
due to the Cilium-specific IP options that could be dropped by an underlying fabric.
Therefore, in case of connectivity issues to services where backends are located on
a remote node from the node that is processing the given NodePort request, it is
advised to first check whether the NodePort request actually arrived on the node
containing the backend. If this was not the case, then switching back to the default
SNAT mode would be advised as a workaround.

Also, in some public cloud provider environments, which implement a source /
destination IP address checking (e.g. AWS), the checking has to be disabled in
order for the DSR mode to work.

The above Helm example configuration in a kube-proxy-free environment with DSR-only mode
enabled would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set tunnel=disabled \\
        --set autoDirectNodeRoutes=true \\
        --set kubeProxyReplacement=strict \\
        --set loadBalancer.mode=dsr \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

.. _Hybrid mode:

Hybrid DSR and SNAT Mode
************************

Cilium also supports a hybrid DSR and SNAT mode, that is, DSR is performed for TCP
and SNAT for UDP connections. This has the advantage that it removes the need for
manual MTU changes in the network while still benefiting from the latency improvements
through the removed extra hop for replies, in particular, when TCP is the main transport
for workloads.

The mode setting ``loadBalancer.mode`` allows to control the behavior through the
options ``dsr``, ``snat`` and ``hybrid``. By default the ``snat`` mode is used in the
agent.

A Helm example configuration in a kube-proxy-free environment with DSR enabled in hybrid
mode would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set tunnel=disabled \\
        --set autoDirectNodeRoutes=true \\
        --set kubeProxyReplacement=strict \\
        --set loadBalancer.mode=hybrid \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

.. _XDP acceleration:

LoadBalancer & NodePort XDP Acceleration
****************************************

Cilium has built-in support for accelerating NodePort, LoadBalancer services and
services with externalIPs for the case where the arriving request needs to be
pushed back out of the node when the backend is located on a remote node. This
ability to act as a "one-legged" / hairpin load balancer can be handled by Cilium
starting from version `1.8 <https://cilium.io/blog/2020/06/22/cilium-18/#kube-proxy-replacement-at-the-xdp-layer>`_ at
the XDP (eXpress Data Path) layer where eBPF is operating directly in the networking
driver instead of a higher layer.

The mode setting ``loadBalancer.acceleration`` allows to enable this acceleration
through the option ``native``. The option ``disabled`` is the default and disables the
acceleration. The majority of drivers supporting 10G or higher rates also support
``native`` XDP on a recent kernel. For cloud based deployments most of these drivers
have SR-IOV variants that support native XDP as well. For on-prem deployments the
Cilium XDP acceleration can be used in combination with LoadBalancer service
implementations for Kubernetes such as `MetalLB <https://metallb.universe.tf/>`_. The
acceleration can be enabled only on a single device which is used for direct routing.

For high-scale environments, also consider tweaking the default map sizes to a larger
number of entries e.g. through setting a higher ``config.bpfMapDynamicSizeRatio``.
See :ref:`bpf_map_limitations` for further details.

The ``loadBalancer.acceleration`` setting is supported for DSR, SNAT and hybrid
modes and can be enabled as follows for ``loadBalancer.mode=hybrid`` in this example:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set tunnel=disabled \\
        --set autoDirectNodeRoutes=true \\
        --set kubeProxyReplacement=strict \\
        --set loadBalancer.acceleration=native \\
        --set loadBalancer.mode=hybrid \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

In case of a multi-device environment, where Cilium's device auto-detection selects
more than a single device to expose NodePort, for example, the Helm option
``devices=eth0`` must be additionally specified for the enablement, where
``eth0`` is the native XDP supported networking device. In that case, the device
name ``eth0`` must be the same on all Cilium managed nodes. Similarly, the underlying
driver for ``eth0`` must have native XDP support on all Cilium managed nodes.

A list of drivers supporting native XDP can be found in the table below. The
corresponding network driver name of an interface can be determined as follows:

.. code-block:: shell-session

    # ethtool -i eth0
    driver: nfp
    [...]

+-------------------+------------+-------------+
| Vendor            | Driver     | XDP Support |
+===================+============+=============+
| Amazon            | ena        | >= 5.6      |
+-------------------+------------+-------------+
| Broadcom          | bnxt_en    | >= 4.11     |
+-------------------+------------+-------------+
| Cavium            | thunderx   | >= 4.12     |
+-------------------+------------+-------------+
| Freescale         | dpaa2      | >= 5.0      |
+-------------------+------------+-------------+
| Intel             | ixgbe      | >= 4.12     |
|                   +------------+-------------+
|                   | ixgbevf    | >= 4.17     |
|                   +------------+-------------+
|                   | i40e       | >= 4.13     |
|                   +------------+-------------+
|                   | ice        | >= 5.5      |
+-------------------+------------+-------------+
| Marvell           | mvneta     | >= 5.5      |
+-------------------+------------+-------------+
| Mellanox          | mlx4       | >= 4.8      |
|                   +------------+-------------+
|                   | mlx5       | >= 4.9      |
+-------------------+------------+-------------+
| Microsoft         | hv_netvsc  | >= 5.6      |
+-------------------+------------+-------------+
| Netronome         | nfp        | >= 4.10     |
+-------------------+------------+-------------+
| Others            | virtio_net | >= 4.10     |
|                   +------------+-------------+
|                   | tun/tap    | >= 4.14     |
+-------------------+------------+-------------+
| Qlogic            | qede       | >= 4.10     |
+-------------------+------------+-------------+
| Socionext         | netsec     | >= 5.3      |
+-------------------+------------+-------------+
| Solarflare        | sfc        | >= 5.5      |
+-------------------+------------+-------------+
| Texas Instruments | cpsw       | >= 5.3      |
+-------------------+------------+-------------+

The current Cilium kube-proxy XDP acceleration mode can also be introspected through
the ``cilium status`` CLI command. If it has been enabled successfully, ``Native``
is shown:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-xxxxx -- cilium status --verbose | grep XDP
      XDP Acceleration:    Native

In the example above, the NodePort XDP acceleration is enabled on the ``eth0`` device
which is also used for direct routing (``DR``).

Note that packets which have been pushed back out of the device for NodePort handling
right at the XDP layer are not visible in tcpdump since packet taps come at a much
later stage in the networking stack. Cilium's monitor or metric counters can be used
instead for gaining visibility.

NodePort XDP on AWS
===================

In order to run with NodePort XDP on AWS, follow the instructions in the :ref:`k8s_install_quick`
guide to set up an EKS cluster or use any other method of your preference to set up a
Kubernetes cluster.

If you are following the EKS guide, make sure to create a node group with SSH access, since
we need few additional setup steps as well as create a larger instance type which supports
the `Elastic Network Adapter <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html>`__ (ena).
As an instance example, ``m5n.xlarge`` is used in the config ``nodegroup-config.yaml``:

.. code-block:: yaml

  apiVersion: eksctl.io/v1alpha5
  kind: ClusterConfig

  metadata:
    name: test-cluster
    region: us-west-2

  nodeGroups:
    - name: ng-1
      instanceType: m5n.xlarge
      desiredCapacity: 2
      ssh:
        allow: true

The nodegroup is created with:

.. code-block:: shell-session

  $ eksctl create nodegroup -f nodegroup-config.yaml

Each of the nodes need the ``kernel-ng`` and ``ethtool`` package installed. The former is
needed in order to run a sufficiently recent kernel for eBPF in general and native XDP
support on the ena driver. The latter is needed to configure channel parameters for the NIC.

.. code-block:: shell-session

  $ IPS=$(kubectl get no -o jsonpath='{$.items[*].status.addresses[?(@.type=="ExternalIP")].address }{"\\n"}' | tr ' ' '\\n')

  $ for ip in $IPS ; do ssh ec2-user@$ip "sudo amazon-linux-extras install -y kernel-ng && sudo yum install -y ethtool && sudo reboot"; done

Once the nodes come back up their kernel version should say ``5.4.58-27.104.amzn2.x86_64`` or
similar through ``uname -r``. In order to run XDP on ena, make sure the driver version is at
least `2.2.8 <https://github.com/amzn/amzn-drivers/commit/ccbb1fe2c2f2ab3fc6d7827b012ba8ec06f32c39>`__.
The driver version can be inspected through ``ethtool -i eth0``. For the given kernel version
the driver version should be reported as ``2.2.10g``.

Before Cilium's XDP acceleration can be deployed, there are two settings needed on the
network adapter side, that is, MTU needs to be lowered in order to be able to operate
with XDP, and number of combined channels need to be adapted.

The default MTU is set to 9001 on the ena driver. Given XDP buffers are linear, they
operate on a single page. A driver typically reserves some headroom for XDP as well
(e.g. for encapsulation purpose), therefore, the highest possible MTU for XDP would
be 3818.

In terms of ena channels, the settings can be gathered via ``ethtool -l eth0``. For the
``m5n.xlarge`` instance, the default output should look like::

  Channel parameters for eth0:
  Pre-set maximums:
  RX:             0
  TX:             0
  Other:          0
  Combined:       4
  Current hardware settings:
  RX:             0
  TX:             0
  Other:          0
  Combined:       4

In order to use XDP the channels must be set to at most 1/2 of the value from
``Combined`` above. Both, MTU and channel changes are applied as follows:

.. code-block:: shell-session

  $ for ip in $IPS ; do ssh ec2-user@$ip "sudo ip link set dev eth0 mtu 3818"; done
  $ for ip in $IPS ; do ssh ec2-user@$ip "sudo ethtool -L eth0 combined 2"; done

In order to deploy Cilium, the Kubernetes API server IP and port is needed:

.. code-block:: shell-session

  $ export API_SERVER_IP=$(kubectl get ep kubernetes -o jsonpath='{$.subsets[0].addresses[0].ip}')
  $ export API_SERVER_PORT=443

Finally, the deployment can be upgraded and later rolled-out with the
``loadBalancer.acceleration=native`` setting to enable XDP in Cilium:

.. parsed-literal::

  helm upgrade cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --reuse-values \\
        --set autoDirectNodeRoutes=true \\
        --set kubeProxyReplacement=strict \\
        --set loadBalancer.acceleration=native \\
        --set loadBalancer.mode=snat \\
        --set k8sServiceHost=$API_SERVER_IP \\
        --set k8sServicePort=$API_SERVER_PORT

NodePort XDP on Azure
=====================

To enable NodePort XDP on Azure AKS or a self-managed Kubernetes running on Azure, the virtual
machines running Kubernetes must have `Accelerated Networking
<https://azure.microsoft.com/en-us/updates/accelerated-networking-in-expanded-preview/>`_
enabled. In addition, the Linux kernel on the nodes must also have support for
native XDP in the ``hv_netvsc`` driver, which is available in kernel >= 5.6 and was backported to
the Azure Linux kernel in 5.4.0-1022.

On AKS, make sure to use the AKS Ubuntu 18.04 node image with Kubernetes version v1.18 which will
provide a Linux kernel with the necessary backports to the ``hv_netvsc`` driver. Please refer to the
documentation on `how to configure an AKS cluster
<https://docs.microsoft.com/en-us/azure/aks/cluster-configuration>`_ for more details.

To enable accelerated networking when creating a virtual machine or
virtual machine scale set, pass the ``--accelerated-networking`` option to the
Azure CLI. Please refer to the guide on how to `create a Linux virtual machine
with Accelerated Networking using Azure CLI
<https://docs.microsoft.com/en-us/azure/virtual-network/create-vm-accelerated-networking-cli>`_
for more details.

When *Accelerated Networking* is enabled, ``lspci`` will show a
Mellanox ConnectX-3 or ConnectX-4 Lx NIC:

.. code-block:: shell-session

    $ lspci | grep Ethernet
    2846:00:02.0 Ethernet controller: Mellanox Technologies MT27710 Family [ConnectX-4 Lx Virtual Function] (rev 80)

In order to run XDP, large receive offload (LRO) needs to be disabled on the
``hv_netvsc`` device. If not the case already, this can be achieved by:

.. code-block:: shell-session

   $ ethtool -K eth0 lro off

NodePort XDP requires Cilium to run in direct routing mode (``tunnel=disabled``).
It is recommended to use Azure IPAM for the pod IP address allocation, which
will automatically configure your virtual network to route pod traffic correctly:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set ipam.mode=azure \\
     --set azure.enabled=true \\
     --set azure.resourceGroup=$AZURE_NODE_RESOURCE_GROUP \\
     --set azure.subscriptionID=$AZURE_SUBSCRIPTION_ID \\
     --set azure.tenantID=$AZURE_TENANT_ID \\
     --set azure.clientID=$AZURE_CLIENT_ID \\
     --set azure.clientSecret=$AZURE_CLIENT_SECRET \\
     --set tunnel=disabled \\
     --set enableIPv4Masquerade=false \\
     --set devices=eth0 \\
     --set kubeProxyReplacement=strict \\
     --set loadBalancer.acceleration=native \\
     --set loadBalancer.mode=hybrid \\
     --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
     --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

When running Azure IPAM on a self-managed Kubernetes cluster, each ``v1.Node``
must have the resource ID of its VM in the ``spec.providerID`` field.
Refer to the :ref:`ipam_azure` reference for more information.

NodePort XDP on GCP
===================

NodePort XDP on the Google Cloud Platform is currently not supported. Both
virtual network interfaces available on Google Compute Engine (the older
virtIO-based interface and the newer `gVNIC
<https://cloud.google.com/compute/docs/instances/create-vm-with-gvnic>`_) are
currently lacking support for native XDP.

.. _NodePort Devices:

NodePort Devices, Port and Bind settings
****************************************

When running Cilium's eBPF kube-proxy replacement, by default, a NodePort or
LoadBalancer service or a service with externalIPs will be accessible through
the IP addresses of native devices which have the default route on the host or
have Kubernetes InternalIP or ExternalIP assigned. InternalIP is preferred over
ExternalIP if both exist. To change the devices, set their names in the
``devices`` Helm option, e.g. ``devices='{eth0,eth1,eth2}'``. Each
listed device has to be named the same on all Cilium managed nodes. Alternatively
if the devices do not match across different nodes, the wildcard option can be 
used, e.g. ``devices=eth+``, which would match any device starting with prefix
``eth``. If no device can be matched the Cilium agent will try to perform auto 
detection.

When multiple devices are used, only one device can be used for direct routing
between Cilium nodes. By default, if a single device was detected or specified
via ``devices`` then Cilium will use that device for direct routing.
Otherwise, Cilium will use a device with Kubernetes InternalIP or ExternalIP
being set. InternalIP is preferred over ExternalIP if both exist. To change
the direct routing device, set the ``nodePort.directRoutingDevice`` Helm
option, e.g. ``nodePort.directRoutingDevice=eth1``. If the direct
routing device does not exist within ``devices``, Cilium will add the
device to the latter list. The direct routing device is used for
:ref:`the NodePort XDP acceleration<XDP Acceleration>` as well (if enabled).

In addition, thanks to the :ref:`host-services` feature, the NodePort service can
be accessed by default from a host or a pod within a cluster via its public, any
local (except for ``docker*`` prefixed names) or loopback address, e.g.
``127.0.0.1:NODE_PORT``.

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``nodePort.range``
option, for example, as ``nodePort.range="10000\,32767"`` for a
range of ``10000-32767``. The default Kubernetes NodePort range is ``30000-32767``.

If the NodePort port range overlaps with the ephemeral port range
(``net.ipv4.ip_local_port_range``), Cilium will append the NodePort range to
the reserved ports (``net.ipv4.ip_local_reserved_ports``). This is needed to
prevent a NodePort service from hijacking traffic of a host local application
which source port matches the service port. To disable the modification of
the reserved ports, set ``nodePort.autoProtectPortRanges`` to ``false``.

By default, the NodePort implementation prevents application ``bind(2)`` requests
to NodePort service ports. In such case, the application will typically see a
``bind: Operation not permitted`` error. This happens either globally for older
kernels or starting from v5.7 kernels only for the host namespace by default
and therefore not affecting any application pod ``bind(2)`` requests anymore. In
order to opt-out from this behavior in general, this setting can be changed for
expert users by switching ``nodePort.bindProtection`` to ``false``.

NodePort with FHRP & VPC
************************

When using Cilium's kube-proxy replacement in conjunction with a
`FHRP <https://en.wikipedia.org/wiki/First-hop_redundancy_protocol>`_
such as VRRP or Cisco's HSRP and VPC (also known as multi-chassis EtherChannel), the default configuration
can cause issues or unwanted traffic flows. This is due to an optimization that causes the source IP of
ingress packets destined for a NodePort to be associated with the corresponding MAC address, and later in
the reply, the MAC address is used as the destination when forwarding the L2 frame, bypassing the FIB lookup.

In such an environment, it may be preferred to instruct Cilium not to attempt this optimization.
This will ensure the response is always forwarded to the MAC address of the currently active FHRP peer, no matter
the origin of the incoming packet.

To disable the optimization set ``bpf.lbBypassFIBLookup`` to ``false``.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=strict \\
        --set bpf.lbBypassFIBLookup=false

.. _Configuring Maps:

Configuring BPF Map Sizes
*************************

For high-scale environments, Cilium's BPF maps can be configured to have higher
limits on the number of entries. Overriding Helm options can be used to tweak
these limits.

To increase the number of entries in Cilium's BPF LB service, backend and
affinity maps consider overriding ``bpf.lbMapMax`` Helm option.
The default value of this LB map size is 65536.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=strict \\
        --set bpf.lbMapMax=131072

.. _kubeproxyfree_hostport:

Container HostPort Support
**************************

Although not part of kube-proxy, Cilium's eBPF kube-proxy replacement also
natively supports ``hostPort`` service mapping without having to use the
Helm CNI chaining option of ``cni.chainingMode=portmap``.

By specifying ``kubeProxyReplacement=strict`` or ``kubeProxyReplacement=probe``
the native hostPort support is automatically enabled and therefore no further
action is required. Otherwise ``hostPort.enabled=true`` can be used to
enable the setting.

If the ``hostPort`` is specified without an additional ``hostIP``, then the
Pod will be exposed to the outside world with the same local addresses from
the node that were detected and used for exposing NodePort services, e.g.
the Kubernetes InternalIP or ExternalIP if set. Additionally, the Pod is also
accessible through the loopback address on the node such as ``127.0.0.1:hostPort``.
If in addition to ``hostPort`` also a ``hostIP`` has been specified for the
Pod, then the Pod will only be exposed on the given ``hostIP`` instead. A
``hostIP`` of ``0.0.0.0`` will have the same behavior as if a ``hostIP`` was
not specified. The ``hostPort`` must not reside in the configured NodePort
port range to avoid collisions.

An example deployment in a kube-proxy-free environment therefore is the same
as in the earlier getting started deployment:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=strict \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

Also, ensure that each node IP is known via ``INTERNAL-IP`` or ``EXTERNAL-IP``,
for example:

.. code-block:: shell-session

    $ kubectl get nodes -o wide
    NAME   STATUS   ROLES    AGE     VERSION   INTERNAL-IP      EXTERNAL-IP   [...]
    apoc   Ready    master   6h15m   v1.17.3   192.168.178.29   <none>        [...]
    tank   Ready    <none>   6h13m   v1.17.3   192.168.178.28   <none>        [...]

If this is not the case, then ``kubelet`` needs to be made aware of it through
specifying ``--node-ip`` through ``KUBELET_EXTRA_ARGS``. Assuming ``eth0`` is
the public facing interface, this can be achieved by:

.. code-block:: shell-session

    $ echo KUBELET_EXTRA_ARGS=\"--node-ip=$(ip -4 -o a show eth0 | awk '{print $4}' | cut -d/ -f1)\" | tee -a /etc/default/kubelet

After updating ``/etc/default/kubelet``, kubelet needs to be restarted.

In order to verify whether the HostPort feature has been enabled in Cilium, the
``cilium status`` CLI command provides visibility through the ``KubeProxyReplacement``
info line. If it has been enabled successfully, ``HostPort`` is shown as ``Enabled``,
for example:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-xxxxx -- cilium status --verbose | grep HostPort
      - HostPort:       Enabled

The following modified example yaml from the setup validation with an additional
``hostPort: 8080`` parameter can be used to verify the mapping:

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: my-nginx
    spec:
      selector:
        matchLabels:
          run: my-nginx
      replicas: 1
      template:
        metadata:
          labels:
            run: my-nginx
        spec:
          containers:
          - name: my-nginx
            image: nginx
            ports:
            - containerPort: 80
              hostPort: 8080

After deployment, we can validate that Cilium's eBPF kube-proxy replacement
exposed the container as HostPort under the specified port ``8080``:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-fmh8d -- cilium service list
    ID   Frontend               Service Type   Backend
    [...]
    5    192.168.178.29:8080    HostPort       1 => 10.29.207.199:80

Similarly, we can inspect through ``iptables`` in the host namespace that
no ``iptables`` rule for the HostPort service is present:

.. code-block:: shell-session

    $ iptables-save | grep HOSTPORT
    [ empty line ]

Last but not least, a simple ``curl`` test shows connectivity for the
exposed HostPort container under the node's IP:

.. code-block:: shell-session

    $ curl 192.168.178.29:8080
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

Removing the deployment also removes the corresponding HostPort from
the ``cilium service list`` dump:

.. code-block:: shell-session

    $ kubectl delete deployment my-nginx

kube-proxy Hybrid Modes
***********************

Cilium's eBPF kube-proxy replacement can be configured in several modes, i.e. it can
replace kube-proxy entirely or it can co-exist with kube-proxy on the system if the
underlying Linux kernel requirements do not support a full kube-proxy replacement.

**Careful:** When deploying the eBPF kube-proxy replacement under co-existence with
kube-proxy on the system, be aware that both mechanisms operate independent of each
other. Meaning, if the eBPF kube-proxy replacement is added or removed on an already
*running* cluster in order to delegate operation from respectively back to kube-proxy,
then it must be expected that existing connections will break since, for example,
both NAT tables are not aware of each other. If deployed in co-existence on a newly
spawned up node/cluster which does not yet serve user traffic, then this is not an
issue.

This section elaborates on the various ``kubeProxyReplacement`` options:

- ``kubeProxyReplacement=strict``: This option expects a kube-proxy-free
  Kubernetes setup where Cilium is expected to fully replace all kube-proxy
  functionality. Once the Cilium agent is up and running, it takes care of handling
  Kubernetes services of type ClusterIP, NodePort, LoadBalancer, services with externalIPs
  as well as HostPort. If the underlying kernel version requirements are not met
  (see :ref:`kubeproxy-free` note), then the Cilium agent will bail out on start-up
  with an error message.

- ``kubeProxyReplacement=probe``: This option is only intended for a hybrid setup,
  that is, kube-proxy is running in the Kubernetes cluster where Cilium partially
  replaces and optimizes kube-proxy functionality. Once the Cilium agent is up and
  running, it probes the underlying kernel for the availability of needed eBPF kernel
  features and, if not present, disables a subset of the functionality in eBPF by
  relying on kube-proxy to complement the remaining Kubernetes service handling. The
  Cilium agent will emit an info message into its log in such case. For example, if
  the kernel does not support :ref:`host-services`, then the ClusterIP translation
  for the node's host-namespace is done through kube-proxy's iptables rules. Also,
  the Cilium agent will set ``nodePort.bindProtection`` to ``false`` in this mode in
  order to defer to kube-proxy for performing the bind-protection of the host namespace.
  This is done to avoid having kube-proxy throw (harmless) warnings to its log stating
  that it could not perform bind calls. In the ``strict`` mode this bind protection is
  performed by Cilium in a more efficient manner with the help of eBPF instead of
  allocating and binding actual sockets.

- ``kubeProxyReplacement=partial``: Similarly to ``probe``, this option is
  intended for a hybrid setup, that is, kube-proxy is running in the Kubernetes cluster
  where Cilium partially replaces and optimizes kube-proxy functionality. As opposed to
  ``probe`` which checks the underlying kernel for available eBPF features and automatically
  disables components responsible for the eBPF kube-proxy replacement when kernel support
  is missing, the ``partial`` option requires the user to manually specify which components
  for the eBPF kube-proxy replacement should be used. When ``kubeProxyReplacement``
  is set to ``partial`` make sure to also set ``enableHealthCheckNodeport`` to
  ``false``, so that the Cilium agent does not start the NodePort health check server.
  Similarly to ``strict`` mode, the Cilium agent will bail out on start-up with an error
  message if the underlying kernel requirements are not met. For fine-grained configuration,
  ``hostServices.enabled``, ``nodePort.enabled``, ``externalIPs.enabled``
  and ``hostPort.enabled`` can be set to ``true``. By default all four options are set
  to ``false``. A few example configurations for the ``partial`` option are provided below.

  The following Helm setup below would be equivalent to ``kubeProxyReplacement=strict``
  in a kube-proxy-free environment:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=partial \\
        --set hostServices.enabled=true \\
        --set nodePort.enabled=true \\
        --set externalIPs.enabled=true \\
        --set hostPort.enabled=true \\
        --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \\
        --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT

  The following Helm setup below would be equivalent to the default Cilium service
  handling in v1.6 or earlier in a kube-proxy environment, that is, serving ClusterIP
  for pods:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=partial

  The following Helm setup below would optimize Cilium's ClusterIP handling for TCP in a
  kube-proxy environment (``hostServices.protocols`` default is ``tcp,udp``):

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=partial \\
        --set hostServices.enabled=true \\
        --set hostServices.protocols=tcp

  The following Helm setup below would optimize Cilium's NodePort, LoadBalancer and services
  with externalIPs handling for external traffic ingressing into the Cilium managed node in
  a kube-proxy environment:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=partial \\
        --set nodePort.enabled=true \\
        --set externalIPs.enabled=true

- ``kubeProxyReplacement=disabled``: This option disables any Kubernetes service
  handling by fully relying on kube-proxy instead, except for ClusterIP services
  accessed from pods (pre-v1.6 behavior).

In Cilium's Helm chart, the default mode is ``kubeProxyReplacement=probe`` for
new deployments.

The current Cilium kube-proxy replacement mode can also be introspected through the
``cilium status`` CLI command:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-xxxxx -- cilium status | grep KubeProxyReplacement
    KubeProxyReplacement:   Strict	[eth0 (DR)]

.. _session-affinity:

Session Affinity
****************

Cilium's eBPF kube-proxy replacement supports Kubernetes service session affinity.
Each connection from the same pod or host to a service configured with
``sessionAffinity: ClientIP`` will always select the same service endpoint.
The default timeout for the affinity is three hours (updated by each request to
the service), but it can be configured through Kubernetes' ``sessionAffinityConfig``
if needed.

The source for the affinity depends on the origin of a request. If a request is
sent from outside the cluster to the service, the request's source IP address is
used for determining the endpoint affinity. If a request is sent from inside
the cluster, the client's network namespace cookie is used. The latter was introduced
in the 5.7 Linux kernel to implement the affinity at the socket layer at which
:ref:`host-services` operate (a source IP is not available there, as the endpoint
selection happens before a network packet has been built by the kernel).

The session affinity support is enabled by default for Cilium's kube-proxy
replacement. For users who run on older kernels which do not support the network
namespace cookies, a fallback in-cluster mode is implemented, which is based on
a fixed cookie value as a trade-off. This makes all applications on the host to
select the same service endpoint for a given service with session affinity configured.
To disable the feature, set ``config.sessionAffinity=false``.

kube-proxy Replacement Health Check server
******************************************
To enable health check server for the kube-proxy replacement, the
``kubeProxyReplacementHealthzBindAddr`` option has to be set (disabled by
default). The option accepts the IP address with port for the health check server
to serve on.
E.g. to enable for IPv4 interfaces set ``kubeProxyReplacementHealthzBindAddr='0.0.0.0:10256'``,
for IPv6 - ``kubeProxyReplacementHealthzBindAddr='[::]:10256'``. The health check server is
accessible via the HTTP ``/healthz`` endpoint.

LoadBalancer Source Ranges Checks
*********************************

When a ``LoadBalancer`` service is configured with ``spec.loadBalancerSourceRanges``,
Cilium's eBPF kube-proxy replacement restricts access from outside (e.g. external
world traffic) to the service to the white-listed CIDRs specified in the field. If
the field is empty, no restrictions for the access will be applied.

When accessing the service from inside a cluster, the kube-proxy replacement will
ignore the field regardless whether it is set. This means that any pod or any host
process in the cluster will be able to access the ``LoadBalancer`` service internally.

The load balancer source range check feature is enabled by default, and it can be
disabled by setting ``config.svcSourceRangeCheck=false``. It makes sense to disable
the check when running on some cloud providers. E.g. `Amazon NLB
<https://kubernetes.io/docs/concepts/services-networking/service/#aws-nlb-support>`__
natively implements the check, so the kube-proxy replacement's feature can be disabled.
Meanwhile `GKE internal TCP/UDP load balancer
<https://cloud.google.com/kubernetes-engine/docs/how-to/internal-load-balancing#lb_source_ranges>`__
does not, so the feature must be kept enabled in order to restrict the access.

Service Proxy Name Configuration
********************************

Like kube-proxy, Cilium also honors the ``service.kubernetes.io/service-proxy-name`` service annotation
and only manages services that contain a matching service-proxy-name label. This name can be configured
by setting ``k8s.serviceProxyName`` option and the behavior is identical to that of
kube-proxy. The service proxy name defaults to an empty string which instructs Cilium to
only manage services not having ``service.kubernetes.io/service-proxy-name`` label.

For more details on the usage of ``service.kubernetes.io/service-proxy-name`` label and its
working, take a look at `this KEP
<https://github.com/kubernetes/enhancements/blob/3ad891202dab1fd5211946f10f31b48003bf8113/keps/sig-network/2447-Make-kube-proxy-service-abstraction-optional/README.md>`__.

.. note::

    If Cilium with a non-empty service proxy name is meant to manage all services in kube-proxy
    free mode, make sure that default Kubernetes services like ``kube-dns`` and ``kubernetes``
    have the required label value.

Troubleshooting
***************

Validate BPF cgroup programs attachment
=======================================

Cilium attaches BPF ``cgroup`` programs to enable socket-based load-balancing (aka
``host-reachable`` services). If you see connectivity issues for ``clusterIP`` services,
check if the programs are attached to the host ``cgroup root``. The default ``cgroup``
root is set to ``/run/cilium/cgroupv2``.
Run the following commands from a Cilium agent pod as well as the underlying
kubernetes node where the pod is running. If the container runtime in your cluster
is running in the cgroup namespace mode, Cilium agent pod can attach BPF ``cgroup``
programs to the ``virtualized cgroup root``. In such cases, Cilium kube-proxy replacement
based load-balancing may not be effective leading to connectivity issues.
For more information, ensure that you have the fix `Pull Request <https://github.com/cilium/cilium/pull/16259>`__.

.. code-block:: shell-session

    $ mount | grep cgroup2
    none on /run/cilium/cgroupv2 type cgroup2 (rw,relatime)

    $ bpftool cgroup tree /run/cilium/cgroupv2/
    CgroupPath
    ID       AttachType      AttachFlags     Name
    /run/cilium/cgroupv2
    10613    device          multi
    48497    connect4
    48493    connect6
    48499    sendmsg4
    48495    sendmsg6
    48500    recvmsg4
    48496    recvmsg6
    48498    getpeername4
    48494    getpeername6

Limitations
###########

    * Cilium's eBPF kube-proxy replacement currently cannot be used with :ref:`gsg_encryption`.
    * Cilium's eBPF kube-proxy replacement relies upon the :ref:`host-services` feature
      which uses eBPF cgroup hooks to implement the service translation. The getpeername(2)
      hook address translation in eBPF is only available for v5.8 kernels. It is known to
      currently not work with libceph deployments.
    * Cilium's eBPF kube-proxy acceleration in XDP can only be used in a single device setup
      as a "one-legged" / hairpin load balancer scenario. In case of a multi-device environment,
      where auto-detection selects more than a single device to expose NodePort, the option
      ``devices=eth0`` must be specified in Helm in order to work, where ``eth0``
      is the native XDP supported networking device.
    * Cilium's DSR NodePort mode currently does not operate well in environments with
      TCP Fast Open (TFO) enabled. It is recommended to switch to ``snat`` mode in this
      situation.
    * Cilium's eBPF kube-proxy replacement does not support the SCTP transport protocol.
      Only TCP and UDP is supported as a transport for services at this point.
    * Cilium's eBPF kube-proxy replacement does not allow ``hostPort`` port configurations
      for Pods that overlap with the configured NodePort range. In such case, the ``hostPort``
      setting will be ignored and a warning emitted to the Cilium agent log. Similarly,
      explicitly binding the ``hostIP`` to the loopback address in the host namespace is
      currently not supported and will log a warning to the Cilium agent log.
    * When Cilium's kube-proxy replacement is used with Kubernetes versions(< 1.19) that have
      support for ``EndpointSlices``, ``Services`` without selectors and backing ``Endpoints``
      don't work. The reason is that Cilium only monitors changes made to ``EndpointSlices``
      objects if support is available and ignores ``Endpoints`` in those cases. Kubernetes 1.19
      release introduces ``EndpointSliceMirroring`` controller that mirrors custom ``Endpoints``
      resources to corresponding ``EndpointSlices`` and thus allowing backing ``Endpoints``
      to work. For a more detailed discussion see :gh-issue:`12438`.
    * As per `k8s Service <https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types>`__,
      Cilium's eBPF kube-proxy replacement disallow access of a ClusterIP service
      from outside a cluster.

Further Readings
################

The following presentations describe inner-workings of the kube-proxy replacement in eBPF
in great details:

    * "Liberating Kubernetes from kube-proxy and iptables" (KubeCon North America 2019, `slides
      <https://docs.google.com/presentation/d/1cZJ-pcwB9WG88wzhDm2jxQY4Sh8adYg0-N3qWQ8593I/edit>`__,
      `video <https://www.youtube.com/watch?v=bIRwSIwNHC0>`__)
    * "Kubernetes service load-balancing at scale with BPF & XDP" (Linux Plumbers 2020, `slides
      <https://linuxplumbersconf.org/event/7/contributions/674/attachments/568/1002/plumbers_2020_cilium_load_balancer.pdf>`__,
      `video <https://www.youtube.com/watch?v=UkvxPyIJAko&t=21s>`__)
    * "eBPF as a revolutionary technology for the container landscape" (Fosdem 2020, `slides
      <https://docs.google.com/presentation/d/1VOUcoIxgM_c6M_zAV1dLlRCjyYCMdR3tJv6CEdfLMh8/edit>`__,
      `video <https://fosdem.org/2020/schedule/event/containers_bpf/>`__)
    * "Kernel improvements for Cilium socket LB" (LSF/MM/BPF 2020, `slides
      <https://docs.google.com/presentation/d/1w2zlpGWV7JUhHYd37El_AUZzyUNSvDfktrF5MJ5G8Bs/edit#slide=id.g746fc02b5b_2_0>`__)
