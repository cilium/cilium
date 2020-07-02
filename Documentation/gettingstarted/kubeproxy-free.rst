.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _kubeproxy-free:

*****************************
Kubernetes without kube-proxy
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

Initialize the control-plane node via ``kubeadm init``, set a pod network
CIDR and skip the ``kube-proxy`` add-on:

.. tabs::

  .. group-tab:: K8s 1.16 and newer

    .. code:: bash

      kubeadm init --pod-network-cidr=10.217.0.0/16 --skip-phases=addon/kube-proxy

  .. group-tab:: K8s 1.15 and older

    In K8s 1.15 and older it is not yet possible to disable kube-proxy via ``--skip-phases=addon/kube-proxy``
    in kubeadm, therefore the below workaround for manually removing the ``kube-proxy`` DaemonSet and
    cleaning the corresponding iptables rules after kubeadm initialization is still necessary (`kubeadm#1733 <https://github.com/kubernetes/kubeadm/issues/1733>`__).

    Initialize control-plane as first step with a given pod network CIDR:

    .. code:: bash

      kubeadm init --pod-network-cidr=10.217.0.0/16

    Then delete the ``kube-proxy`` DaemonSet and remove its iptables rules as following:

    .. code:: bash

      kubectl -n kube-system delete ds kube-proxy
      iptables-restore <(iptables-save | grep -v KUBE)

Afterwards, join worker nodes by specifying the control-plane node IP address and
the token returned by ``kubeadm init``:

.. code:: bash

   kubeadm join <..>

.. note::

    Please ensure that
    `kubelet <https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/>`_'s
    ``--node-ip`` is set correctly on each worker if you have multiple interfaces.
    Cilium's kube-proxy replacement may not work correctly otherwise.
    You can validate this by running ``kubectl get nodes -o wide`` to see whether
    each node has an ``InternalIP`` which is assigned to a device with the same
    name on each node.

.. include:: k8s-install-download-release.rst

Next, generate the required YAML files and deploy them. **Important:** Replace
``API_SERVER_IP`` and ``API_SERVER_PORT`` below with the concrete control-plane
node IP address and the kube-apiserver port number reported by ``kubeadm init``
(usually, it is port ``6443``).

Specifying this is necessary as ``kubeadm init`` is run explicitly without setting
up kube-proxy and as a consequence while it exports ``KUBERNETES_SERVICE_HOST``
and ``KUBERNETES_SERVICE_PORT`` with a ClusterIP of the kube-apiserver service
to the environment, there is no kube-proxy in our setup provisioning that service.
The Cilium agent therefore needs to be made aware of this information through below
configuration.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set config.ipam=kubernetes \\
        --set global.kubeProxyReplacement=strict \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

This will install Cilium as a CNI plugin with the BPF kube-proxy replacement to
implement handling of Kubernetes services of type ClusterIP, NodePort, LoadBalancer
and services with externalIPs. On top of that the BPF kube-proxy replacement also
supports hostPort for containers such that using portmap is not necessary anymore.

Finally, as a last step, verify that Cilium has come up correctly on all nodes and
is ready to operate:

.. parsed-literal::

    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-fmh8d        1/1       Running   0          10m
    cilium-mkcmb        1/1       Running   0          10m

Note, in above helm configuration the ``kubeProxyReplacement`` has been set to
``strict`` mode. This means that the Cilium agent will bail out in case the
underlying Linux kernel support is missing.

Without explicitly specifying a ``kubeProxyReplacement`` option, helm uses
``kubeProxyReplacement`` with ``probe`` by default which would automatically
disable a subset of the features to implement the kube-proxy replacement instead
of bailing out if the kernel support is missing. This makes the assumption that
Cilium's BPF kube-proxy replacement would co-exist with kube-proxy on the system
to optimize Kubernetes services. Given we've used kubeadm to explicitly deploy
a kube-proxy-free setup, the ``strict`` mode has been used instead to ensure
that we do not rely on a (non-existing) fallback.

Cilium's BPF kube-proxy replacement is supported in direct routing as well as in
tunneling mode.

Validate the Setup
##################

After deploying Cilium with above Quick-Start guide, we can first validate that
the Cilium agent is running in the desired mode:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-fmh8d -- cilium status | grep KubeProxyReplacement
    KubeProxyReplacement:   Strict	[eth0 (DR), eth1]	[NodePort (SNAT, 30000-32767, XDP: NONE), HostPort, ExternalIPs, HostReachableServices (TCP, UDP)]

As a next, optional step, we deploy nginx pods, create a new NodePort service and
validate that Cilium installed the service correctly.

The following yaml is used for the backend pods:

.. parsed-literal::

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

.. parsed-literal::

    kubectl get pods -l run=my-nginx -o wide
    NAME                        READY   STATUS    RESTARTS   AGE   IP             NODE   NOMINATED NODE   READINESS GATES
    my-nginx-756fb87568-gmp8c   1/1     Running   0          62m   10.217.0.149   apoc   <none>           <none>
    my-nginx-756fb87568-n5scv   1/1     Running   0          62m   10.217.0.107   apoc   <none>           <none>

In the next step, we create a NodePort service for the two instances:

.. parsed-literal::

    kubectl expose deployment my-nginx --type=NodePort --port=80
    service/my-nginx exposed

Verify that the NodePort service has been created:

.. parsed-literal::

    kubectl get svc my-nginx
    NAME       TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
    my-nginx   NodePort   10.104.239.135   <none>        80:31940/TCP   24m

With the help of the ``cilium service list`` command, we can validate that
Cilium's BPF kube-proxy replacement created the new NodePort services under
port ``31940`` (one for each of devices ``eth0`` and ``eth1``):

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-fmh8d -- cilium service list
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

At the same time we can inspect through ``iptables`` in the host namespace
that no ``iptables`` rule for the service is present:

.. parsed-literal::

    iptables-save | grep KUBE-SVC
    [ empty line ]

Last but not least, a simple ``curl`` test shows connectivity for the exposed
NodePort port ``31940`` as well as for the ClusterIP:

.. parsed-literal::

    curl 127.0.0.1:31940
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

.. parsed-literal::

    curl 192.168.178.29:31940
    <!doctype html>
    <html>
    <head>
    <title>welcome to nginx!</title>
    [....]

.. parsed-literal::

    curl 172.16.0.29:31940
    <!doctype html>
    <html>
    <head>
    <title>welcome to nginx!</title>
    [....]

.. parsed-literal::

    curl 10.104.239.135:80
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

As can be seen, the Cilium's BPF kube-proxy replacement is set up correctly.

Advanced Configuration
######################

This section covers a few advanced configuration modes for the kube-proxy replacement
that go beyond the above Quick-Start guide and are entirely optional.

Client Source IP Preservation
*****************************

Cilium's BPF kube-proxy replacement implements a number of options in order to avoid
performing SNAT on NodePort requests where the client source IP address would otherwise
be lost on its path to the service endpoint.

- ``externalTrafficPolicy=Local``: The ``Local`` policy is generally supported through
  the BPF implementation. In-cluster connectivity for services with ``externalTrafficPolicy=Local``
  is possible and can also be reached from nodes which have no local backends, meaning,
  given SNAT does not need to be performed, all service endpoints are available for
  load balancing from in-cluster side.

- ``externalTrafficPolicy=Cluster``: For the ``Cluster`` policy which is the default
  upon service creation, multiple options exist for achieving client source IP preservation
  for external traffic, that is, operating the kube-proxy replacement in :ref:`DSR<DSR Mode>`
  or :ref:`Hybrid<Hybrid Mode>` mode if only TCP-based services are exposed to the outside
  world for the latter.

.. _DSR mode:

Direct Server Return (DSR)
**************************

By default, Cilium's BPF NodePort implementation operates in SNAT mode. That is,
when node-external traffic arrives and the node determines that the backend for
the LoadBalancer, NodePort or services with externalIPs is at a remote node, then the
node is redirecting the request to the remote backend on its behalf by performing
SNAT. This does not require any additional MTU changes at the cost that replies
from the backend need to make the extra hop back that node in order to perform the
reverse SNAT translation there before returning the packet directly to the external
client.

This setting can be changed through the ``global.nodePort.mode`` helm option to
``dsr`` in order to let Cilium's BPF NodePort implementation operate in DSR mode.
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

Above helm example configuration in a kube-proxy-free environment with DSR-only mode
enabled would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set config.ipam=kubernetes \\
        --set global.tunnel=disabled \\
        --set global.autoDirectNodeRoutes=true \\
        --set global.kubeProxyReplacement=strict \\
        --set global.nodePort.mode=dsr \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

.. _Hybrid mode:

Hybrid DSR and SNAT Mode
************************

Cilium also supports a hybrid DSR and SNAT mode, that is, DSR is performed for TCP
and SNAT for UDP connections. This has the advantage that it removes the need for
manual MTU changes in the network while still benefiting from the latency improvements
through the removed extra hop for replies, in particular, when TCP is the main transport
for workloads.

The mode setting ``global.nodePort.mode`` allows to control the behavior through the
options ``dsr``, ``snat`` and ``hybrid``. By default the ``snat`` mode is used in the
agent.

A helm example configuration in a kube-proxy-free environment with DSR enabled in hybrid
mode would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set config.ipam=kubernetes \\
        --set global.tunnel=disabled \\
        --set global.autoDirectNodeRoutes=true \\
        --set global.kubeProxyReplacement=strict \\
        --set global.nodePort.mode=hybrid \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

.. _XDP acceleration:

LoadBalancer & NodePort XDP Acceleration
****************************************

Cilium has built-in support for accelerating NodePort, LoadBalancer services and
services with externalIPs for the case where the arriving request needs to be
pushed back out of the node when the backend is located on a remote node. This
ability to act as a "one-legged" / hairpin load balancer can be handled by Cilium
starting from version `1.8 <https://cilium.io/blog/2020/06/22/cilium-18/#kube-proxy-replacement-at-the-xdp-layer>`_ at
the XDP (eXpress Data Path) layer where BPF is operating directly in the networking
driver instead of a higher layer.

The mode setting ``global.nodePort.acceleration`` allows to enable this acceleration
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

The ``global.nodePort.acceleration`` setting is supported for DSR, SNAT and hybrid
modes and can be enabled as follows for ``nodePort.mode=hybrid`` in this example:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.tunnel=disabled \\
        --set global.autoDirectNodeRoutes=true \\
        --set global.kubeProxyReplacement=strict \\
        --set global.nodePort.acceleration=native \\
        --set global.nodePort.mode=hybrid \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

In case of a multi-device environment, where Cilium's device auto-detection selects
more than a single device to expose NodePort, for example, the helm option
``global.devices=eth0`` must be additionally specified for the enablement, where
``eth0`` is the native XDP supported networking device. In that case, the device
name ``eth0`` must be the same on all Cilium managed nodes. Similarly, the underlying
driver for ``eth0`` must have native XDP support on all Cilium managed nodes.

A list of drivers supporting native XDP can be found in the table below. The
corresponding network driver name of an interface can be determined as follows:

.. parsed-literal::

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
the ``cilium status`` CLI command. If it has been enabled successfully, ``XDP: NATIVE``
is shown:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-xxxxx -- cilium status | grep KubeProxyReplacement
    KubeProxyReplacement:   Strict      [eth0 (DR)]     [NodePort (SNAT, 30000-32767, XDP: NATIVE), HostPort, ExternalIPs, HostReachableServices (TCP, UDP)]

In the example above, the NodePort XDP acceleration is enabled on the ``eth0`` device
which is also used for direct routing (``DR``).

Note that packets which have been pushed back out of the device for NodePort handling
right at the XDP layer are not visible in tcpdump since packet taps come at a much
later stage in the networking stack. Cilium's monitor or metric counters can be used
instead for gaining visibility.

NodePort XDP on AWS
===================

In order to run with NodePort XDP on AWS, follow the instructions in the :ref:`k8s_install_eks`
guide to set up an EKS cluster or use any other method of your preference to set up a
Kubernetes cluster.

If you are following the EKS guide, make sure to create a node group with SSH access, since
we need few additional setup steps as well as create a larger instance type which supports
the `Elastic Network Adapter <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html>`__ (ena).
As an instance example, ``m5n.xlarge`` is used in the config ``nodegroup-config.yaml``:

.. parsed-literal::

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

.. parsed-literal::

  eksctl create nodegroup -f nodegroup-config.yaml

Each of the nodes need the ``kernel-ng`` and ``ethtool`` package installed. The former is
needed in order to run a sufficiently recent kernel for eBPF in general and native XDP
support on the ena driver. The latter is needed to configure channel parameters for the NIC.

.. parsed-literal::

  IPS=$(kubectl get no -o jsonpath='{$.items[*].status.addresses[?(@.type=="ExternalIP")].address }{"\\n"}' | tr ' ' '\\n')

  for ip in $IPS ; do ssh ec2-user@$ip "sudo amazon-linux-extras install -y kernel-ng && sudo ethtool install -y ethtool && sudo reboot"; done

Once the nodes come back up their kernel version should say ``5.4.38-17.76.amzn2.x86_64`` or
similar through ``uname -r``. In order to run XDP on ena, make sure the driver version is at
least `2.2.8 <https://github.com/amzn/amzn-drivers/commit/ccbb1fe2c2f2ab3fc6d7827b012ba8ec06f32c39>`__.
The driver version can be inspected through ``ethtool -i eth0``.

.. note::

  If the reported driver version is <2.2.8, a new version of the ena driver needs to be built
  and installed according to the instructions given `here <https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/rpm/README-rpm.txt>`__.
  For kernel-ng version ``5.4.38-17.76.amzn2.x86_64`` a prebuild rpm of ena driver version
  2.2.9g can be downloaded `here <https://gist.github.com/tklauser/268641aea4fced9e8c3b4a2f7536661b#file-kmod-ena-2-2-9-1-amzn2-25-x86_64-rpm>`__
  for testing purposes.

Before Cilium's XDP acceleration can be deployed, there are two settings needed on the
network adapter side, that is, MTU needs to be lowered in order to be able to operate
with XDP, and number of combined channels need to be adapted.

The default MTU is set to 9001 on the ena driver. Given XDP buffers are linear, they
operate on a single page. A driver typically reserves some headroom for XDP as well
(e.g. for encapsulation purpose), therefore, the highest possible MTU for XDP would
be 3818.

In terms of ena channels, the settings can be gathered via ``ethtool -l eth0``. For the
``m5n.xlarge`` instance, the default output should look like:

.. parsed-literal::

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

.. parsed-literal::

  for ip in $IPS ; do ssh ec2-user@$ip "sudo ip link set dev eth0 mtu 3818"; done
  for ip in $IPS ; do ssh ec2-user@$ip "sudo ethtool -L eth0 combined 2"; done

In order to deploy Cilium, the Kubernetes API server IP and port is needed:

.. parsed-literal::

  export API_SERVER_IP=$(kubectl get ep kubernetes -o jsonpath='{$.subsets[0].addresses[0].ip}')
  export API_SERVER_PORT=443

Finally, the deployment can be upgraded and later rolled-out with the
``global.nodePort.acceleration=native`` setting to enable XDP in Cilium:

.. parsed-literal::

  helm upgrade cilium ./cilium \\
        --namespace kube-system \\
        --reuse-values \\
        --set global.autoDirectNodeRoutes=true \\
        --set global.kubeProxyReplacement=strict \\
        --set global.nodePort.acceleration=native \\
        --set global.nodePort.mode=snat \\
        --set global.k8sServiceHost=$API_SERVER_IP \\
        --set global.k8sServicePort=$API_SERVER_PORT

NodePort XDP on Azure
=====================

To enable NodePort XDP on a self-managed Kubernetes running on Azure, the
virtual machines running Kubernetes must have `Accelerated Networking
<https://azure.microsoft.com/en-us/updates/accelerated-networking-in-expanded-preview/>`_
enabled. In addition, the Linux kernel on the nodes must also have support for
native XDP in the ``hv_netvsc`` driver, which is available in kernel >= 5.6.

To enable accelerated networking when creating a virtual machine or
virtual machine scale set, pass the ``--accelerated-networking`` option to the
Azure CLI. Please refer to the guide on how to `create a Linux virtual machine
with Accelerated Networking using Azure CLI
<https://docs.microsoft.com/en-us/azure/virtual-network/create-vm-accelerated-networking-cli>`_
for more details.

When *Accelerated Networking* is enabled, ``lspci`` will show a
Mellanox ConnectX-3 or ConnectX-4 Lx NIC:

.. parsed-literal::

    $ lspci | grep Ethernet
    2846:00:02.0 Ethernet controller: Mellanox Technologies MT27710 Family [ConnectX-4 Lx Virtual Function] (rev 80)

In order to run XDP, large receive offload (LRO) needs to be disabled on the
``hv_netvsc`` device. If not the case already, this can be achieved by:

.. parsed-literal::

  ethtool -K eth0 lro off

NodePort XDP requires Cilium to run in direct routing mode (``tunnel=disabled``).
It is recommended to use Azure IPAM for the pod IP address allocation, which
will automatically configure your virtual network to route pod traffic correctly:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set config.ipam=azure \\
     --set global.azure.enabled=true \\
     --set global.azure.resourceGroup=AZURE_NODE_RESOURCE_GROUP \\
     --set global.azure.subscriptionID=AZURE_SUBSCRIPTION_ID \\
     --set global.azure.tenantID=AZURE_TENANT_ID \\
     --set global.azure.clientID=AZURE_CLIENT_ID \\
     --set global.azure.clientSecret=AZURE_CLIENT_SECRET \\
     --set global.tunnel=disabled \\
     --set global.masquerade=false \\
     --set global.kubeProxyReplacement=strict \\
     --set global.nodePort.acceleration=native \\
     --set global.nodePort.mode=hybrid \\
     --set global.k8sServiceHost=API_SERVER_IP \\
     --set global.k8sServicePort=API_SERVER_PORT

When running Azure IPAM on a self-managed Kubernetes cluster, each ``v1.Node``
must have the resource ID of its VM in the ``spec.providerID`` field.
Refer to the :ref:`ipam_azure` reference for more information.

.. _NodePort Devices:

NodePort Devices, Port and Bind settings
****************************************

When running Cilium's BPF kube-proxy replacement, by default, a NodePort or
LoadBalancer service or a service with externalIPs will be accessible through
the IP addresses of native devices which have the default route on the host or
have Kubernetes InternalIP or ExternalIP assigned. InternalIP is preferred over
ExternalIP if both exist. To change the devices, set their names in the
``global.devices`` helm option, e.g. ``global.devices='{eth0,eth1,eth2}'``. Each
listed device has to be named the same on all Cilium managed nodes.

When multiple devices are used, only one device can be used for direct routing
between Cilium nodes. By default, if a single device was detected or specified
via ``global.devices`` then Cilium will use that device for direct routing.
Otherwise, Cilium will use a device with Kubernetes InternalIP or ExternalIP
being set. InternalIP is preferred over ExternalIP if both exist. To change
the direct routing device, set the ``global.nodePort.directRoutingDevice`` helm
option, e.g. ``global.nodePort.directRoutingDevice=eth1``. If the direct
routing device does not exist within ``global.devices``, Cilium will add the
device to the latter list. The direct routing device is used for
:ref:`the NodePort XDP acceleration<XDP Acceleration>` as well (if enabled).

In addition, thanks to the :ref:`host-services` feature, the NodePort service can
be accessed by default from a host or a pod within a cluster via its public, any
local (except for ``docker*`` prefixed names) or loopback address, e.g.
``127.0.0.1:NODE_PORT``.

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``global.nodePort.range``
option, for example, as ``global.nodePort.range="10000\,32767"`` for a
range of ``10000-32767``. The default Kubernetes NodePort range is ``30000-32767``.

If the NodePort port range overlaps with the ephemeral port range
(``net.ipv4.ip_local_port_range``), Cilium will append the NodePort range to
the reserved ports (``net.ipv4.ip_local_reserved_ports``). This is needed to
prevent a NodePort service from hijacking traffic of a host local application
which source port matches the service port. To disable the modification of
the reserved ports, set ``global.nodePort.autoProtectPortRanges`` to ``false``.

By default, the NodePort implementation prevents application ``bind(2)`` requests
to NodePort service ports. In such case, the application will typically see a
``bind: Operation not permitted`` error. This happens either globally for older
kernels or starting from v5.7 kernels only for the host namespace by default
and therefore not affecting any application pod ``bind(2)`` requests anymore. In
order to opt-out from this behavior in general, this setting can be changed for
expert users by switching ``global.nodePort.bindProtection`` to ``false``.

.. _kubeproxyfree_hostport:

Container hostPort support
**************************

Although not part of kube-proxy, Cilium's BPF kube-proxy replacement also
natively supports ``hostPort`` service mapping without having to use the
Helm CNI chaining option of ``global.cni.chainingMode=portmap``.

By specifying ``global.kubeProxyReplacement=strict`` or ``global.kubeProxyReplacement=probe``
the native hostPort support is automatically enabled and therefore no further
action is required. Otherwise ``global.hostPort.enabled=true`` can be used to
enable the setting.

An example deployment in a kube-proxy-free environment therefore is the same
as in the earlier getting started deployment:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set config.ipam=kubernetes \\
        --set global.kubeProxyReplacement=strict \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

Also, ensure that each node IP is known via ``INTERNAL-IP`` or ``EXTERNAL-IP``,
for example:

.. parsed-literal::

    kubectl get nodes -o wide
    NAME   STATUS   ROLES    AGE     VERSION   INTERNAL-IP      EXTERNAL-IP   [...]
    apoc   Ready    master   6h15m   v1.17.3   192.168.178.29   <none>        [...]
    tank   Ready    <none>   6h13m   v1.17.3   192.168.178.28   <none>        [...]

If this is not the case, then ``kubelet`` needs to be made aware of it through
specifying ``--node-ip`` through ``KUBELET_EXTRA_ARGS``. Assuming ``eth0`` is
the public facing interface, this can be achieved by:

.. parsed-literal::

    echo KUBELET_EXTRA_ARGS=\"--node-ip=$(ip -4 -o a show eth0 | awk '{print $4}' | cut -d/ -f1)\" | tee -a /etc/default/kubelet

After updating ``/etc/default/kubelet``, kubelet needs to be restarted.

In order to verify whether the HostPort feature has been enabled in Cilium, the
``cilium status`` CLI command provides visibility through the ``KubeProxyReplacement``
info line. If it has been enabled successfully, ``HostPort`` is shown, for example:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-xxxxx -- cilium status | grep KubeProxyReplacement
    KubeProxyReplacement:   Strict   [eth0 (DR)]   [NodePort (SNAT, 30000-32767, XDP: DISABLED), HostPort, ExternalIPs, HostReachableServices (TCP, UDP), SessionAffinity]

The following modified example yaml from the setup validation with an additional
``hostPort: 8080`` parameter can be used to verify the mapping:

.. parsed-literal::

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

After deployment, we can validate that Cilium's BPF kube-proxy replacement
exposed the container as HostPort under the specified port ``8080``:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-fmh8d -- cilium service list
    ID   Frontend               Service Type   Backend
    [...]
    5    192.168.178.29:8080    HostPort       1 => 10.29.207.199:80

Similarly, we can inspect through ``iptables`` in the host namespace that
no ``iptables`` rule for the HostPort service is present:

.. parsed-literal::

    iptables-save | grep HOSTPORT
    [ empty line ]

Last but not least, a simple ``curl`` test shows connectivity for the
exposed HostPort container under the node's IP:

.. parsed-literal::

    curl 192.168.178.29:8080
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

Removing the deployment also removes the corresponding HostPort from
the ``cilium service list`` dump:

.. parsed-literal::

    kubectl delete deployment my-nginx

kube-proxy Hybrid Modes
***********************

Cilium's BPF kube-proxy replacement can be configured in several modes, i.e. it can
replace kube-proxy entirely or it can co-exist with kube-proxy on the system if the
underlying Linux kernel requirements do not support a full kube-proxy replacement.

This section therefore elaborates on the various ``global.kubeProxyReplacement`` options:

- ``global.kubeProxyReplacement=strict``: This option expects a kube-proxy-free
  Kubernetes setup where Cilium is expected to fully replace all kube-proxy
  functionality. Once the Cilium agent is up and running, it takes care of handling
  Kubernetes services of type ClusterIP, NodePort, LoadBalancer, services with externalIPs
  as well as HostPort. If the underlying kernel version requirements are not met
  (see :ref:`kubeproxy-free` note), then the Cilium agent will bail out on start-up
  with an error message.

- ``global.kubeProxyReplacement=probe``: This option is intended for a hybrid setup,
  that is, kube-proxy is running in the Kubernetes cluster where Cilium partially
  replaces and optimizes kube-proxy functionality. Once the Cilium agent is up and
  running, it probes the underlying kernel for the availability of needed BPF kernel
  features and, if not present, disables a subset of the functionality in BPF by
  relying on kube-proxy to complement the remaining Kubernetes service handling. The
  Cilium agent will emit an info message into its log in such case. For example, if
  the kernel does not support :ref:`host-services`, then the ClusterIP translation
  for the node's host-namespace is done through kube-proxy's iptables rules.

- ``global.kubeProxyReplacement=partial``: Similarly to ``probe``, this option is
  intended for a hybrid setup, that is, kube-proxy is running in the Kubernetes cluster
  where Cilium partially replaces and optimizes kube-proxy functionality. As opposed to
  ``probe`` which checks the underlying kernel for available BPF features and automatically
  disables components responsible for the BPF kube-proxy replacement when kernel support
  is missing, the ``partial`` option requires the user to manually specify which components
  for the BPF kube-proxy replacement should be used. Similarly to ``strict`` mode, the
  Cilium agent will bail out on start-up with an error message if the underlying kernel
  requirements are not met. For fine-grained configuration, ``global.hostServices.enabled``,
  ``global.nodePort.enabled``, ``global.externalIPs.enabled`` and ``global.hostPort.enabled``
  can be set to ``true``. By default all four options are set to ``false``. A few example
  configurations for the ``partial`` option are provided below.

  The following helm setup below would be equivalent to ``global.kubeProxyReplacement=strict``
  in a kube-proxy-free environment:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set config.ipam=kubernetes \\
        --set global.kubeProxyReplacement=partial \\
        --set global.hostServices.enabled=true \\
        --set global.nodePort.enabled=true \\
        --set global.externalIPs.enabled=true \\
        --set global.hostPort.enabled=true \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

  The following helm setup below would be equivalent to the default Cilium service
  handling in v1.6 or earlier in a kube-proxy environment, that is, serving ClusterIP
  for pods:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial

  The following helm setup below would optimize Cilium's ClusterIP handling for TCP in a
  kube-proxy environment (``global.hostServices.protocols`` default is ``tcp,udp``):

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial \\
        --set global.hostServices.enabled=true \\
        --set global.hostServices.protocols=tcp

  The following helm setup below would optimize Cilium's NodePort, LoadBalancer and services
  with externalIPs handling for external traffic ingressing into the Cilium managed node in
  a kube-proxy environment:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial \\
        --set global.nodePort.enabled=true \\
        --set global.externalIPs.enabled=true

- ``global.kubeProxyReplacement=disabled``: This option disables any Kubernetes service
  handling by fully relying on kube-proxy instead, except for ClusterIP services
  accessed from pods if cilium-agent's flag ``--disable-k8s-services`` is set to
  ``false`` (pre-v1.6 behavior).

In Cilium's helm chart, the default mode is ``global.kubeProxyReplacement=probe`` for
new deployments.

For existing Cilium deployments in version v1.6 or prior, please consult the :ref:`1.7_upgrade_notes`.

The current Cilium kube-proxy replacement mode can also be introspected through the
``cilium status`` CLI command:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-xxxxx -- cilium status | grep KubeProxyReplacement
    KubeProxyReplacement:   Strict	[eth0 (DR)]	[NodePort (SNAT, 30000-32767, XDP: NONE), HostPort, ExternalIPs, HostReachableServices (TCP, UDP)]

Session Affinity
****************

Cilium's BPF kube-proxy replacement supports Kubernetes service session affinity.
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

Limitations
###########

    * Cilium's BPF kube-proxy replacement currently cannot be used with :ref:`encryption`.
    * Cilium's BPF kube-proxy replacement relies upon the :ref:`host-services` feature
      which uses BPF cgroup hooks to implement the service translation. The getpeername(2)
      hook address translation in BPF is only available for v5.8 kernels. It is known to
      currently not work with libceph deployments.
    * Cilium's BPF kube-proxy acceleration in XDP can only be used in a single device setup
      as a "one-legged" / hairpin load balancer scenario. In case of a multi-device environment,
      where auto-detection selects more than a single device to expose NodePort, the option
      ``global.devices=eth0`` must be specified in helm in order to work, where ``eth0``
      is the native XDP supported networking device.
    * Cilium's DSR NodePort mode currently does not operate well in environments with
      TCP Fast Open (TFO) enabled. It is recommended to switch to ``snat`` mode in this
      situation.

Further Readings
################

The following presentations describe inner-workings of the kube-proxy replacement in BPF
in great details:

    * "Liberating Kubernetes from kube-proxy and iptables" (KubeCon North America 2019, `slides
      <https://docs.google.com/presentation/d/1cZJ-pcwB9WG88wzhDm2jxQY4Sh8adYg0-N3qWQ8593I/edit>`__,
      `video <https://www.youtube.com/watch?v=bIRwSIwNHC0>`__)
    * "BPF as a revolutionary technology for the container landscape" (Fosdem 2020, `slides
      <https://docs.google.com/presentation/d/1VOUcoIxgM_c6M_zAV1dLlRCjyYCMdR3tJv6CEdfLMh8/edit>`__,
      `video <https://fosdem.org/2020/schedule/event/containers_bpf/>`__)
    * "Kernel improvements for Cilium socket LB" (LSF/MM/BPF 2020, `slides
      <https://docs.google.com/presentation/d/1w2zlpGWV7JUhHYd37El_AUZzyUNSvDfktrF5MJ5G8Bs/edit#slide=id.g746fc02b5b_2_0>`__)

