.. _admin_guide:

Administrator Guide
===================

This document describes how to install, configure, run, and troubleshoot Cilium
in different deployment modes. It focuses on a full deployment of Cilium within
a datacenter or public cloud. If you are just looking for a simple way to
experiment, we highly recommend trying out the :ref:`gs_guide` instead.

This guide assumes that you have read the :ref:`arch_guide` which explains all
the components and concepts.

.. _admin_system_reqs:

System Requirements
-------------------

Before installing Cilium. Please ensure that your system is meeting the minimal
requirements to run Cilium. Most modern Linux distributions will automatically
meet the requirements.

Summary
^^^^^^^

When running Cilium using the container image ``cilium/cilium``, these are
the requirements your system has to fulfill:

- `Linux kernel`_ >= 4.8 (>= 4.9.17 LTS recommended)
- Key-Value store (see :ref:`req_kvstore` for version details)

The following additional dependencies are **only** required if you choose to
run Cilium natively and you are **not** using ``cilium/cilium`` container
image:

- `clang+LLVM`_ >=3.7.1
- iproute2_ >= 4.8.0

Linux Distribution Compatibility Matrix
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following table lists Linux distributions versions which are known to work
well with Cilium.

===================== ================
Distribution          Minimal Version
===================== ================
CoreOS_               stable
Debian_               >= 9 Stretch
`Fedora Atomic/Core`_ >= 25
LinuxKit_             all
Ubuntu_               >= 16.10
===================== ================

.. _CoreOS: https://coreos.com/releases/
.. _Debian: https://wiki.debian.org/DebianStretch
.. _Fedora Atomic/Core: http://www.projectatomic.io/blog/2017/03/fedora_atomic_2week_2/
.. _LinuxKit: https://github.com/linuxkit/linuxkit/tree/master/kernel
.. _Ubuntu: https://wiki.ubuntu.com/YakketyYak/ReleaseNotes#Linux_kernel_4.8

.. note:: The above list is composed based on feedback by users, if you have
          good experience with a particular Linux distribution which is not
          listed below, please let us know by opening a GitHub issue or by
          creating a pull request to update this guide.


.. _admin_kernel_version:

Linux Kernel
^^^^^^^^^^^^

Cilium leverages and builds on the kernel functionality BPF as well as various
subsystems which integrate with BPF. Therefore, all systems that will run a
Cilium agent are required to run the Linux kernel version 4.8.0 or later.

The 4.8.0 kernel is the minimal kernel version required, more recent kernels may
provide additional BPF functionality. Cilium will automatically detect
additional available functionality by probing for the functionality when the
agent starts.

In order for the BPF feature to be enabled properly, the following kernel
configuration options must be enabled. This is typically the case automatically
with distribution kernels. If an option provides the choice to build as module
or statically linked, then both choices are valid.

.. code:: bash

        CONFIG_BPF=y
        CONFIG_BPF_SYSCALL=y
        CONFIG_NET_CLS_BPF=y
        CONFIG_BPF_JIT=y
        CONFIG_NET_CLS_ACT=y
        CONFIG_NET_SCH_INGRESS=y
        CONFIG_CRYPTO_SHA1=y
        CONFIG_CRYPTO_USER_API_HASH=y

.. _req_kvstore:

Key-Value store
^^^^^^^^^^^^^^^

Cilium uses a distributed Key-Value store to manage and distribute security
identities across all cluster nodes. The following Key-Value stores are
currently supported:

- etcd >= 3.1.0
- consul >= 0.6.4

See section :ref:`admin_kvstore` for details on how to configure the
`cilium-agent` to use a Key-Value store.

clang+LLVM
^^^^^^^^^^

.. note:: This requirement is only needed if you run ``cilium-agent`` natively.
          If you are using the Cilium container image ``cilium/cilium``,
          clang+LLVM is included in the container image.

LLVM is the compiler suite which Cilium uses to generate BPF bytecode before
loading the programs into the Linux kernel.  The minimal version of LLVM
installed on the system is >=3.7.1. The version of clang installed must be
compiled with the BPF backend enabled.

See http://releases.llvm.org/ for information on how to download and install
LLVM.  Be aware that in order to use clang 3.9.x, the kernel version
requirement is >= 4.9.17.

iproute2
^^^^^^^^

.. note:: This requirement is only needed if you run ``cilium-agent`` natively.
          If you are using the Cilium container image ``cilium/cilium``,
          iproute2 is included in the container image.

iproute2 is a low level tool used to configure various networking related
subsystems of the Linux kernel. Cilium uses iproute2 to configure networking
and ``tc`` which is part of iproute2 to load BPF programs into the kernel.

The minimal version of iproute2_ installed must be >= 4.8.0. Please see
https://www.kernel.org/pub/linux/utils/net/iproute2/ for documentation on how
to install iproute2.

.. _admin_install_daemonset:

Installation on Kubernetes
--------------------------

This section describes how to install and run Cilium on Kubernetes. The
deployment method we are using is called DaemonSet_ which is the easiest way to deploy
Cilium in a Kubernetes environment. It will request Kubernetes to automatically
deploy and run a ``cilium/cilium`` container image as a pod on all Kubernetes
worker nodes.

Should you encounter any issues during the installation, please refer to the
:ref:`admin_k8s_troubleshooting` section and / or seek help on `Slack channel`_.

TL;DR Version (Expert Mode)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you know what you are doing, then the following quick instructions get you
started in the shortest time possible. If you require additional details or are
looking to customize the installation then read the remaining sections of this
chapter.

1. Mount the BPF filesystem on all k8s worker nodes. There are many ways to
   achieve this, see section :ref:`admin_mount_bpffs` for more details.

.. code:: bash

	mount bpffs /sys/fs/bpf -t bpf

2. Download the DaemonSet_ template ``cilium-ds.yaml`` and specify the k8s API
   server and Key-Value store addresses:

.. code:: bash

    $ wget https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/cilium-ds.yaml
    $ vim cilium-ds.yaml
    [adjust --k8s-api-server or --k8s-kubeconfig-path]
    [adjust --kvstore and --kvstore-opts]

3. Deploy the ``cilium`` and ``cilium-consul`` DaemonSet_

.. code:: bash

    $ kubectl create -f cilium-ds.yaml
    daemonset "cilium-consul" created
    daemonset "cilium" created

    $ kubectl get ds --namespace kube-system
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          1         1         1         <none>          2m
    cilium-consul   1         1         1         <none>          2m

.. _admin_mount_bpffs:

Mounting the BPF FS 
^^^^^^^^^^^^^^^^^^^

This step is optional but recommended. It allows the ``cilium-agent`` to pin
BPF resources to a persistent filesystem and make them persistent across
restarts of the agent. If the BPF filesystem is not mounted in the host
filesystem, Cilium will automatically mount the filesystem in the mount
namespace of the container when the agent starts. This will allow operation of
Cilium but will result in unmounting of the filesystem when the pod is
restarted. This in turn will cause resources such as the connection tracking
table of the BPF programs to be released which will cause all connections into
local containers to be dropped. Mounting the BPF filesystem in the host mount
namespace will ensure that the agent can be restarted without affecting
connectivity of any pods.

In order to mount the BPF filesystem, the following command must be run in the
host mount namespace. The command must only be run once during the boot process
of the machine.

.. code:: bash

	mount bpffs /sys/fs/bpf -t bpf

A portable way to achieve this with persistence is to add the following line to
`/etc/fstab` and then run `mount /sys/fs/bpf`. This will cause the filesystem
to be automatically mounted when the node boots.

.. code:: bash

     bpffs			/sys/fs/bpf		bpf	defaults 0 0

If you are using systemd to manage the kubelet, another option is to add a
``ExecStartPre`` line in the ``/etc/systemd/kubelet.service`` file as follows:

.. code:: bash

	[Service]
        ExecStartPre=/bin/bash -c ' \\
                if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
                   /bin/mount bpffs /sys/fs/bpf -t bpf; \\
                fi'


CNI Configuation
^^^^^^^^^^^^^^^^

CNI_ - Container Network Interface is the plugin layer used by Kubernetes to
delegate networking configuration. You can find additional information on the
CNI_ project website.

.. note:: Kubernetes `` >= 1.3.5`` requires the ``loopback`` CNI plugin to be
          installed on all worker nodes. The binary is typically provided by
          most Kubernetes distributions. See section :ref:`install_cni` for
          instructions on how to install CNI in case the ``loopback`` binary
          is not already installed on your worker nodes.

CNI configuration is automatically being taken care of when deploying Cilium
via the provided DaemonSet_. The script ``cni-install.sh`` is automatically run
via the ``postStart`` mechanism when the ``cilium`` pod is started.

.. note:: In order for the the ``cni-install.sh`` script to work properly, the
          ``kubelet`` task must either be running on the host filesystem of the
          worder node, or the ``/etc/cni/net.d`` and ``/opt/cni/bin``
          directories must be mounted into the container where ``kubelet`` is
          running. This can be achieved with Volumes_ mounts.

The CNI auto installation is performed as follows:

1. The ``/etc/cni/net.d`` and ``/opt/cni/bin`` directories are mounted from the
   host filesystem into the pod where Cilium is running.

2. The file ``/etc/cni/net.d/10-cilium.conf`` is written in case it does not
   exist yet.

3. The binary ``cilium-cni`` is installed to ``/opt/cni/bin``. Any existing
   binary with the name ``cilium-cni`` is overwritten.

.. _install_cni:

Installing CNI and loopback
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since Kubernetes ``v1.3.5`` the ``loopback`` CNI_ plugin must be installed.
There are many ways to install CNI_, the following is an example:

.. code:: bash

    sudo mkdir -p /opt/cni
    wget https://storage.googleapis.com/kubernetes-release/network-plugins/cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz
    sudo tar -xvf cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz -C /opt/cni
    rm cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz

Adjusting CNI configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to adjust the CNI configuration you may do so by creating the CNI
configuration ``/etc/cni/net.d/10-cilium.conf`` manually:

.. code:: bash

    sudo mkdir -p /etc/cni/net.d
    sudo sh -c 'echo "{
        "name": "cilium",
        "type": "cilium-cni",
        "mtu": 1450
    }
    " > /etc/cni/net.d/10-cilium.conf'

Cilium will use any existing ``/etc/cni/net.d/10-cilium.conf`` file if it
already exists on a worker node and only creates it if it does not exist yet.


.. _rbac_integration:

RBAC integration
^^^^^^^^^^^^^^^^

If you have RBAC_ enabled in your Kubernetes cluster, create appropriate
cluster roles and service accounts for Cilium:

.. code:: bash

    $ kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/rbac.yaml
    clusterrole "cilium" created
    serviceaccount "cilium" created
    clusterrolebinding "cilium" created

.. _ds_config:

Configuring the DaemonSet
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

    $ wget https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/cilium-ds.yaml
    $ vim cilium-ds.yaml

The following configuration options *must* be specified:

- ``--k8s-api-server`` or ``--k8s-kubeconfig-path`` must point to at least one
  Kubernetes API server address.
- ``--kvstore`` with optional ``--kvstore-opts`` to configure the Key-Value
  store.  See section :ref:`admin_kvstore` for additional details on how to
  configure the Key-Value store.

.. _ds_deploy:

Deploying the DaemonSet
^^^^^^^^^^^^^^^^^^^^^^^

After configuring the ``cilium`` DaemonSet_ it is time to deploy it using
``kubectl``:

.. code:: bash

    $ kubectl create -f cilium-ds.yaml

Kubernetes will deploy the ``cilium`` and ``cilium-consul`` DaemonSet_ as a pod
in the ``kube-system`` namespace on all worker nodes. This operation is
performed in the background. Run the following command to check the progress of
the deployment:

.. code:: bash

    $ kubectl --namespace kube-system get ds
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          4         4         4         <none>          2m
    cilium-consul   4         4         4         <none>          2m


As the pods are deployed, the number in the ready column will increase and
eventually reach the desired count.

.. code:: bash

        $ kubectl --namespace kube-system describe ds cilium
        Name:		cilium
        Image(s):	cilium/cilium:stable
        Selector:	io.cilium.admin.daemon-set=cilium,name=cilium
        Node-Selector:	<none>
        Labels:		io.cilium.admin.daemon-set=cilium
                        name=cilium
        Desired Number of Nodes Scheduled: 1
        Current Number of Nodes Scheduled: 1
        Number of Nodes Misscheduled: 0
        Pods Status:	1 Running / 0 Waiting / 0 Succeeded / 0 Failed
        Events:
          FirstSeen	LastSeen	Count	From		SubObjectPath	Type		Reason			Message
          ---------	--------	-----	----		-------------	--------	------			-------
          35s		35s		1	{daemon-set }			Normal		SuccessfulCreate	Created pod: cilium-2xzqm


We can now check the logfile of a particular cilium agent:

.. code:: bash

	$ kubectl --namespace kube-system get pods
        NAME           READY     STATUS    RESTARTS   AGE
        cilium-2xzqm   1/1       Running   0          41m

        $ kubectl --namespce kube-system logs cilium-2xzqm
        INFO      _ _ _
        INFO  ___|_| |_|_ _ _____
        INFO |  _| | | | | |     |
        INFO |___|_|_|_|___|_|_|_|
        INFO Cilium 0.8.90 f022e2f Thu, 27 Apr 2017 23:17:56 -0700 go version go1.7.5 linux/amd64
        INFO clang and kernel versions: OK!
        INFO linking environment: OK!
        [...]


Deploying to selected nodes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To deploy Cilium only to a selected list of worker nodes, you can add a
NodeSelector_ to the ``cilium-ds.yaml`` file like this:

.. code:: bash

    spec:
      template:
        spec:
          nodeSelector:
            with-network-plugin: cilium

And then label each node where Cilium should be deployed:

.. code:: bash

    kubectl label node worker0 with-network-plugin=cilium
    kubectl label node worker1 with-network-plugin=cilium
    kubectl label node worker2 with-network-plugin=cilium

Networking For Existing Pods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In case pods were already running before the Cilium DaemonSet was deployed,
these pods will still be connected using the previous networking plugin
according to the CNI configuration. A typical example for this is the
``kube-dns`` service which runs in the ``kube-system`` namespace by default.

A simple way to change networking for such existing pods is to rely on the fact
that Kubernetes automatically restarts pods in a Deployment if they are
deleted, so we can simply delete the original kube-dns pod and the replacment
pod started immediately after will have networking managed by Cilium.  In a
production deployment, this step could be performed as a rolling update of
kube-dns pods to avoid downtime of the DNS service.

::

        $ kubectl --namespace kube-system delete pods -l k8s-app=kube-dns
        pod "kube-dns-268032401-t57r2" deleted

Running ``kubectl get pods`` will show you that Kubernetes started a new set of
``kube-dns`` pods while at the same time terminating the old pods:

::

        $ kubectl --namespace kube-system get pods
        NAME                          READY     STATUS        RESTARTS   AGE
        cilium-5074s                  1/1       Running       0          58m
        cilium-consul-plxdm           1/1       Running       0          58m
        kube-addon-manager-minikube   1/1       Running       0          59m
        kube-dns-268032401-j0vml      3/3       Running       0          9s
        kube-dns-268032401-t57r2      3/3       Terminating   0          57m

Removing the cilium daemon
^^^^^^^^^^^^^^^^^^^^^^^^^^

All cilium agents are managed as a DaemonSet_ which means that deleting the
DaemonSet_ will automatically stop and remove all pods which run Cilium on each
worker node:

.. code:: bash

        $ kubectl --namespace kube-system delete ds cilium
        $ kubectl --namespace kube-system delete ds cilium-consul

.. _admin_k8s_troubleshooting:

Troubleshooting
^^^^^^^^^^^^^^^

Check the status of the DaemonSet_ and verify that all desired instances are in
"ready" state:

.. code:: bash

        $ kubectl --namespace kube-system get ds
        NAME      DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
        cilium    1         1         0         <none>          3s

In this example, we see a desired state of 1 with 0 being ready. This indicates
a problem. The next step is to list all cilium pods by matching on the label
``k8s-app=cilium`` and also sort the list by the restart count of each pod to
easily identify the failing pods:

.. code:: bash

        $ kubectl --namespace kube-system get pods --selector k8s-app=cilium \
                  --sort-by='.status.containerStatuses[0].restartCount'
        NAME           READY     STATUS             RESTARTS   AGE
        cilium-813gf   0/1       CrashLoopBackOff   2          44s

Pod ``cilium-813gf`` is failing and has already been restarted 2 times. Let's
print the logfile of that pod to investigate the cause:

.. code:: bash

        $ kubectl --namespace kube-system logs cilium-813gf
        INFO      _ _ _
        INFO  ___|_| |_|_ _ _____
        INFO |  _| | | | | |     |
        INFO |___|_|_|_|___|_|_|_|
        INFO Cilium 0.8.90 f022e2f Thu, 27 Apr 2017 23:17:56 -0700 go version go1.7.5 linux/amd64
        CRIT kernel version: NOT OK: minimal supported kernel version is >= 4.8

In this example, the cause for the failure is a Linux kernel running on the
worker node which is not meeting :ref:`admin_system_reqs`.

If the cause for the problem is not apparent based on these simple steps,
please come and seek help on our `Slack channel`_.

.. _admin_install_docker_compose:

Installation using Docker Compose
---------------------------------

This section describes how to install & run the Cilium container image using
Docker compose.

Note: for multi-host deployments using a key-value store, you would want to
update this template to point cilium to a central key-value store.

.. code:: bash

    $ wget https://raw.githubusercontent.com/cilium/cilium/master/examples/docker-compose/docker-compose.yml
    $ IFACE=eth1 docker-compose up
    [...]

.. code:: bash

    $ docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium cilium
    $ docker run -d --name foo --net cilium --label id.foo tgraf/nettools sleep 30000
    $ docker run -d --name bar --net cilium --label id.bar tgraf/nettools sleep 30000

.. code:: bash

    $ docker exec -ti foo ping6 -c 4 bar
    PING f00d::c0a8:66:0:f236(f00d::c0a8:66:0:f236) 56 data bytes
    64 bytes from f00d::c0a8:66:0:f236: icmp_seq=1 ttl=63 time=0.086 ms
    64 bytes from f00d::c0a8:66:0:f236: icmp_seq=2 ttl=63 time=0.062 ms
    64 bytes from f00d::c0a8:66:0:f236: icmp_seq=3 ttl=63 time=0.061 ms
    64 bytes from f00d::c0a8:66:0:f236: icmp_seq=4 ttl=63 time=0.064 ms

    --- f00d::c0a8:66:0:f236 ping statistics ---
    4 packets transmitted, 4 received, 0% packet loss, time 3066ms
    rtt min/avg/max/mdev = 0.061/0.068/0.086/0.011 ms

.. _admin_install_source:

Installation From Source
------------------------

If for some reason you do not want to run Cilium as a contaimer image.
Installing it from source is possible as well. It does come with additional
dependencies described in :ref:`admin_system_reqs`.

1. Download & extract the latest Cilium release from the ReleasesPage_

.. _ReleasesPage: https://github.com/cilium/cilium/releases

.. code:: bash

    $ wget https://github.com/cilium/cilium/archive/v0.9.0.tar.gz
    $ tar xzvf v0.9.0.tar.gz
    $ cd cilium-0.9.0

2. Build & install the Cilium binaries to ``bindir``

.. code:: bash

   $ make
   $ sudo make install

3. Optional: Install systemd/upstart init files:

.. code:: bash

    sudo cp contrib/upstart/* /etc/init/
    service cilium start


Container Node Network Configuration
------------------------------------

The networking configuration required on your Linux container node
depends on the IP interconnectivity model in use and whether the
deployment requires containers in the cluster to reach or be reached by
resources outside the cluster.  For more details, see the
Architecture Guide's section on :ref:`arch_ip_connectivity`.

Overlay Mode - Container-to-Container Access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With overlay mode, container-to-container access does not require
additional network configuration on the Linux container node, as
overlay connectivity is handled by Cilium itself, and the physical
network only sees IP traffic destined to / from the Linux node IP address.

The use of Overlay Mode is configured by passing a ``--tunnel`` or ``-t``
flag to the Cilium indicating the type of encapsulation to be used.  Valid
options include ``vxlan`` and ``geneve``.


Direct Mode - Container-to-Container Access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In direct mode, container traffic is sent to the underlying network
unencapsulated, and thus that network must understand how to route
a packet to the right destination Linux node running the container.

Direct mode is used if no ``-t`` or ``--tunneling`` flag is passed to the
Cilium agent at startup.

Cilium automatically enables IP forwarding in Linux when direct mode is
configured, but it is up to the container cluster administrator to
ensure that each routing element in the underlying network has a route
that describe each node IP as the IP next hop for the corresponding
node prefix.

If the underlying network is a physical datacenter network, this can be
achieved by running a routing daemon on each Linux node that participates
in the datacenter's routing protocol, such as bird,
zebra or radvd.   Configuring this setup is beyond the
scope of this document.

If the underlying network is a virtual network in a public cloud, that cloud
provider likely provides APIs to configure the routing behavior of that virtual
network (e.g,. `AWS VPC Route Tables`_ or `GCE Routes`_). These APIs can be
used to associate each node prefix with the appropriate next hop IP each time a
container node is added to the cluster.

An example using GCE Routes for this is available
`here <https://github.com/cilium/cilium/blob/gce-example/examples/gce/docs/07-network.md>`_ .

.. _AWS VPC Route Tables: http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Route_Tables.html
.. _GCE Routes: https://cloud.google.com/compute/docs/reference/latest/routes

External Network Access
^^^^^^^^^^^^^^^^^^^^^^^

By default with Cilium, containers use IP addresses that are private to the
cluster.  This is very common in overlay mode, but may also be the case even
if direct mode is being used. In either scenario, if a container with a private
IP should be allowed to make outgoing network connections to resources
either elsewhere in the data center or on the public Internet, the Linux node
should be configured to perform IP masquerading, also known as network
address port translation (NAPT), for all traffic destined from a container to the outside world.

An example of configuring IP masquerading for IPv6 is:

::

    ip6tables -t nat -I POSTROUTING -s f00d::/112 -o em1 -j MASQUERADE

This will masquerade all packets with a source IP in the cluster prefix
``beef::/64`` with the public IPv6 address of the Linux nodes primary network
interface ``em1``.  If you change your cluster IP address or use IPv4 instead
of IPv6, be sure to update this command accordingly.

Testing External Connectivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

IPv6 external connectivity can be tested with:

.. code:: bash

    ip -6 route get `host -t aaaa www.google.com | awk '{print $5}'`
    ping6 www.google.com

If the default route is missing, your VM may not be receiving router
advertisements. In this case, the default route can be added manually:

.. code:: bash

    ip -6 route add default via beef::1

The following tests connectivity from a container to the outside world:

.. code:: bash

    $ sudo docker run --rm -ti --net cilium -l client cilium/demo-client ping6 www.google.com
    PING www.google.com(zrh04s07-in-x04.1e100.net) 56 data bytes
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=1 ttl=56 time=7.84 ms
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=2 ttl=56 time=8.63 ms
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=3 ttl=56 time=8.83 ms

.. _admin_agent_config:

Agent Configuration
-------------------

.. _admin_kvstore:

Key-Value Store
^^^^^^^^^^^^^^^

+---------------------+--------------------------------------+----------------------+
| Option              | Description                          | Default              |
+---------------------+--------------------------------------+----------------------+
| --kvstore TYPE      | Key Value Store Type:                |                      |
|                     | (consul, etcd, local)                |                      |
+---------------------+--------------------------------------+----------------------+
| --kvstore-opt OPTS  | Local:                               |                      |
+---------------------+--------------------------------------+----------------------+

consul
~~~~~~

When using consul, the consul agent address needs to be provided with the
``consul.address``:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| consul.address      | Address | Address of consul agent                           |
+---------------------+---------+---------------------------------------------------+

etcd
~~~~

When using etcd, one of the following options need to be provided to configure the
etcd endpoints:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| etcd.address        | Address | Address of etcd endpoint                          |
+---------------------+---------+---------------------------------------------------+
| etcd.config         | Path    | Path to an etcd configuration file.               |
+---------------------+---------+---------------------------------------------------+

.. _admin_agent_options:

Command Line Options
^^^^^^^^^^^^^^^^^^^^

+---------------------+--------------------------------------+----------------------+
| Option              | Description                          | Default              |
+---------------------+--------------------------------------+----------------------+
| config              | config file                          | $HOME/ciliumd.yaml   |
+---------------------+--------------------------------------+----------------------+
| debug               | Enable debug messages                | false                |
+---------------------+--------------------------------------+----------------------+
| device              | Ethernet device to snoop on          |                      |
+---------------------+--------------------------------------+----------------------+
| disable-conntrack   | Disable connection tracking          | false                |
+---------------------+--------------------------------------+----------------------+
| enable-policy       | Enable policy enforcement            | default              |
|                     | (default, false, true)               |                      |
+---------------------+--------------------------------------+----------------------+
| docker              | Docker socket endpoint               |                      |
+---------------------+--------------------------------------+----------------------+
| enable-tracing      | enable policy tracing                |                      |
+---------------------+--------------------------------------+----------------------+
| nat46-range         | IPv6 range to map IPv4 addresses to  |                      |
+---------------------+--------------------------------------+----------------------+
| k8s-api-server      | Kubernetes api address server        |                      |
+---------------------+--------------------------------------+----------------------+
| k8s-kubeconfig-path | Absolute path to the kubeconfig file |                      |
+---------------------+--------------------------------------+----------------------+
| keep-config         | When restoring state, keeps          | false                |
|                     | containers' configuration in place   |                      |
+---------------------+--------------------------------------+----------------------+
| kvstore             | Key Value Store Type:                |                      |
|                     | (consul, etcd, local)                |                      |
+---------------------+--------------------------------------+----------------------+
| kvstore-opt         | Local:                               |                      |
|                     |    - None                            |                      |
|                     | Etcd:                                |                      |
|                     |    - etcd.address: Etcd agent        |                      |
|                     |      address.                        |                      |
|                     |    - etcd.config: Absolute path to   |                      |
|                     |      the etcd configuration file.    |                      |
|                     | Consul:                              |                      |
|                     |    - consul.address: Consul agent    |                      |
|                     |      agent address.                  |                      |
+---------------------+--------------------------------------+----------------------+
| label-prefix-file   | file with label prefixes cilium      |                      |
|                     | Cilium should use for policy         |                      |
+---------------------+--------------------------------------+----------------------+
| labels              | list of label prefixes Cilium should |                      |
|                     | use for policy                       |                      |
+---------------------+--------------------------------------+----------------------+
| logstash            | enable logstash integration          | false                |
+---------------------+--------------------------------------+----------------------+
| logstash-agent      | logstash agent address and port      | 127.0.0.1:8080       |
+---------------------+--------------------------------------+----------------------+
| node-address        | IPv6 address of the node             |                      |
+---------------------+--------------------------------------+----------------------+
| restore             | Restore state from previously        | false                |
|                     | running version of the agent         |                      |
+---------------------+--------------------------------------+----------------------+
| keep-templates      | do not restore templates from binary | false                |
+---------------------+--------------------------------------+----------------------+
| state-dir           | path to store runtime state          |                      |
+---------------------+--------------------------------------+----------------------+
| lib-dir             | path to store runtime build env      |                      |
+---------------------+--------------------------------------+----------------------+
| socket-path         | path for agent unix socket           |                      |
+---------------------+--------------------------------------+----------------------+
| lb                  | enables load-balancing mode on       |                      |
|                     | interface 'device'                   |                      |
+---------------------+--------------------------------------+----------------------+
| disable-ipv4        | disable IPv4 mode                    | false                |
+---------------------+--------------------------------------+----------------------+
| ipv4-range          | IPv4 prefix                          |                      |
+---------------------+--------------------------------------+----------------------+
| tunnel              | Overlay/tunnel mode (vxlan/geneve)   | vxlan                |
+---------------------+--------------------------------------+----------------------+
| bpf-root            | Path to mounted BPF filesystem       |                      |
+---------------------+--------------------------------------+----------------------+
| access-log          | Path to HTTP access log              |                      |
+---------------------+--------------------------------------+----------------------+

Cilium Client Commands
----------------------

Endpoint Management
^^^^^^^^^^^^^^^^^^^

TODO

Policy
^^^^^^

TODO

Loadbalancing / Services
^^^^^^^^^^^^^^^^^^^^^^^^

TODO

Troubleshooting
---------------

If you running Cilium in Kubernetes, see the Kubernetes specific section
:ref:`admin_k8s_troubleshooting`.

Logfiles
^^^^^^^^

The main source for information when troubleshooting is the logfile.

Monitoring Packet Drops
^^^^^^^^^^^^^^^^^^^^^^^

When connectivity is not as it should. A main cause an be unwanted packet drops
on the networking level. There can be various causes for this. The easiest way
to track packet drops and identify their cause is to use ``cilium monitor``.

.. code:: bash

    $ cilium monitor
    Listening for events on 2 CPUs with 64x4096 of shared memory
    Press Ctrl-C to quit

    CPU 00: MARK 0x14126c56 FROM 56326 Packet dropped 159 (Policy denied (L4)) 94 bytes ifindex=18
    00000000  02 fd 7f 53 22 c8 66 56  da 2e fb 84 86 dd 60 0c  |...S".fV......`.|
    00000010  12 14 00 28 06 3f f0 0d  00 00 00 00 00 00 0a 00  |...(.?..........|
    00000020  02 0f 00 00 00 ad f0 0d  00 00 00 00 00 00 0a 00  |................|
    00000030  02 0f 00 00 dc 06 ca 5c  00 50 70 28 32 21 00 00  |.......\.Pp(2!..|
    00000040  00 00 a0 02 6c 98 d5 1b  00 00 02 04 05 6e 04 02  |....l........n..|
    00000050  08 0a 01 5f 07 80 00 00  00 00 01 03 03 07 00 00  |..._............|
    00000060  00 00 00 00                                       |....|

The above indicates that a packet from endpoint ID `56326` has been dropped due
to violation of the Layer 4 policy.

Tracing Policy Decision
^^^^^^^^^^^^^^^^^^^^^^^

If Cilium is denying connections which it shouldn't. There is an easy way to
verify if and why Cilium is denying connectivity in between particular
endpoints. The following example shows how to use ``cilium policy trace`` to
simulate a policy decision from an endpoint with the label ``id.curl`` to an
endpoint with the label ``id.http`` on port 80:

.. code:: bash

    $ cilium policy trace -s id.curl -d id.httpd --dport 80
    Tracing From: [container:id.curl] => To: [container:id.httpd] Ports: [80/any]
    * Rule 2 {"matchLabels":{"any:id.httpd":""}}: match
        Allows from labels {"matchLabels":{"any:id.curl":""}}
    +     Found all required labels
    1 rules matched
    Result: ALLOWED
    L3 verdict: allowed

    Resolving egress port policy for [container:id.curl]
    * Rule 0 {"matchLabels":{"any:id.curl":""}}: match
      Allows Egress port [{80 tcp}]
    1 rules matched
    L4 egress verdict: allowed

    Resolving ingress port policy for [container:id.httpd]
    * Rule 2 {"matchLabels":{"any:id.httpd":""}}: match
      Allows Ingress port [{80 tcp}]
    1 rules matched
    L4 ingress verdict: allowed

    Verdict: allowed


Debugging the datapath
^^^^^^^^^^^^^^^^^^^^^^

The tool ``cilium monitor`` can also be used to retrieve debugging information
from the BPF based datapath. Debugging messages are sent if either the
``cilium-agent`` itself or the respective endpoint is in debug mode. The debug
mode of the agent can be enabled by starting ``cilium-agent`` with the option
``--debug`` enabled or by running ``cilium config debug=true`` for an already
running agent. Debugging of an individual endpoint can be enabled by running
``cilium endpoint config ID Debug=true``


.. code:: bash

    $ cilium endpoint config 29381 Debug=true
    Endpoint 29381 configuration updated successfully
    $ cilium monitor
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: 118 bytes Incoming packet from container ifindex 20
    00000000  3a f3 07 b3 c6 7f 4e 76  63 5c 53 4e 86 dd 60 02  |:.....Nvc\SN..`.|
    00000010  7a 3c 00 40 3a 40 f0 0d  00 00 00 00 00 00 0a 00  |z<.@:@..........|
    00000020  02 0f 00 00 36 7d f0 0d  00 00 00 00 00 00 0a 00  |....6}..........|
    00000030  02 0f 00 00 ff ff 81 00  c7 05 4a 32 00 05 29 98  |..........J2..).|
    00000040  2c 59 00 00 00 00 1d cd  0c 00 00 00 00 00 10 11  |,Y..............|
    00000050  12 13 14 15 16 17 18 19  1a 1b 1c 1d 1e 1f 20 21  |.............. !|
    00000060  22 23 24 25 26 27 28 29  2a 2b 2c 2d 2e 2f 30 31  |"#$%&'()*+,-./01|
    00000070  32 33 34 35 36 37 00 00                           |234567..|

    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: Handling ICMPv6 type=129
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: CT reverse lookup: sport=0 dport=32768 nexthdr=58 flags=1
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: CT entry found lifetime=24026, proxy_port=0 revnat=0
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: CT verdict: Reply, proxy_port=0 revnat=0
    CPU 01: MARK 0x3c7a42a5 FROM 13949 DEBUG: Going to host, policy-skip=1
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT reverse lookup: sport=2048 dport=0 nexthdr=1 flags=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT lookup address: 10.15.0.1
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT lookup: sport=0 dport=2048 nexthdr=1 flags=1
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT verdict: New, proxy_port=0 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT created 1/2: sport=0 dport=2048 nexthdr=1 flags=1 proxy_port=0 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT created 2/2: 10.15.42.252 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: CT created 1/2: sport=0 dport=0 nexthdr=1 flags=3 proxy_port=0 revnat=0
    CPU 00: MARK 0x4010f7f3 FROM 13949 DEBUG: 98 bytes Delivery to ifindex 20
    00000000  4e 76 63 5c 53 4e 3a f3  07 b3 c6 7f 08 00 45 00  |Nvc\SN:.......E.|
    00000010  00 54 d8 41 40 00 3f 01  24 4d 0a 0f 00 01 0a 0f  |.T.A@.?.$M......|
    00000020  2a fc 08 00 67 03 4a 4f  00 01 2a 98 2c 59 00 00  |*...g.JO..*.,Y..|
    00000030  00 00 24 e8 0c 00 00 00  00 00 10 11 12 13 14 15  |..$.............|
    00000040  16 17 18 19 1a 1b 1c 1d  1e 1f 20 21 22 23 24 25  |.......... !"#$%|
    00000050  26 27 28 29 2a 2b 2c 2d  2e 2f 30 31 32 33 34 35  |&'()*+,-./012345|
    00000060  36 37 00 00 00 00 00 00                           |67......|

.. _Slack channel: https://cilium.herokuapp.com
.. _DaemonSet: https://kubernetes.io/docs/admin/daemons/
.. _NodeSelector: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
.. _RBAC: https://kubernetes.io/docs/admin/authorization/rbac/
.. _CNI: https://github.com/containernetworking/cni
.. _Volumes: https://kubernetes.io/docs/tasks/configure-pod-container/configure-volume-storage/

.. _iproute2: https://www.kernel.org/pub/linux/utils/net/iproute2/
.. _llvm: http://releases.llvm.org/
.. _Linux kernel: https://www.kernel.org/
