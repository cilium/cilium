.. _admin_guide:

Administrator Guide
===================

This document describes how to install, configure, and troubleshoot Cilium in different deployment modes.

It assumes you have already read and understood the components and concepts described in the :ref:`arch_guide`.

This document focuses on a full deployment of Cilium within a datacenter or public cloud.  If you are just looking
for a simple way to experiment on your laptop, we highly recommend using our Vagrant environment:

.. toctree::

   vagrant


.. _admin_kernel_version:

System Requirements
-------------------

Linux Kernel
^^^^^^^^^^^^

Cilium leverages and builds on the kernel functionality BPF as well as various
subsystems which integrate with BPF. Therefore, all systems that will run a
Cilium agent are required to run the Linux kernel version 4.8.0 or later.

In order for the BPF feature to be enabled properly, the following kernel
configuration options must be enabled. This is typically the case automatically
with distribution kernels. If an option provides the choice to build as module
or statically linked, then both choices are valid.

::

        CONFIG_BPF=y
        CONFIG_BPF_SYSCALL=y
        CONFIG_NET_CLS_BPF=y
        CONFIG_BPF_JIT=y
        CONFIG_NET_CLS_ACT=y
        CONFIG_NET_SCH_INGRESS=y
        CONFIG_CRYPTO_SHA1=y
        CONFIG_CRYPTO_USER_API_HASH=y

These requirements are met on most modern container workload focused Linux
distributions:

=================== ========== ===================================================
Distribution        Version    More information
=================== ========== ===================================================
CoreOS              stable     https://coreos.com/releases/
Debian              9 Stretch  https://wiki.debian.org/DebianStretch
Fedora Atomic/Core  25         http://www.projectatomic.io/blog/2017/03/fedora_atomic_2week_2/
LinuxKit            all        https://github.com/linuxkit/linuxkit/tree/master/kernel
Ubuntu              16.10      https://wiki.ubuntu.com/YakketyYak/ReleaseNotes#Linux_kernel_4.8
=================== ========== ===================================================

The 4.8.0 kernel is minimal kernel version required, more recent kernels may
provide additional BPF functionality. Cilium will automatically detect
additional available functionality by probing for the functionality when the
agent starts.

clang+LLVM
^^^^^^^^^^

.. note:: This requirement is only needed if you run ``cilium-agent`` natively
          as binary. If you are using the Cilium container image
          ``cilium/cilium``, this dependency/prerequisite is shipped as part of
          the container image.

clang+LLVM >=3.7.1: http://releases.llvm.org/

Please note that in order to use clang 3.9.x, the kernel version requirement is
>= 4.9.17

iproute2
^^^^^^^^^

.. note:: This requirement is only needed if you run ``cilium-agent`` natively
          as binary. If you are using the Cilium container image
          ``cilium/cilium``, this dependency/prerequisite is shipped as part of
          the container image.

iproute2 >= 4.8.0: https://www.kernel.org/pub/linux/utils/net/iproute2/

Installation
------------

Cilium consists of an agent plus additional optional integration plugins
which must be installed on all servers which will run containers.

The easiest way to leverage the Cilium agent on your Linux container node is
to install it as a container itself.  This section will cover that option for
both vanilla Docker deployments as well as Kubernetes.  It will also describe
how to build and install from source in the case that you need to run Cilium
directly on the Linux container host without a container.

Installing Cilium using Kubernetes DaemonSets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The easiest way of deploying Cilium in an existing Kubernetes cluster is to use
a `DaemonSet <https://kubernetes.io/docs/admin/daemons/>`_. This will
automatically deploy and run a ``cilium/cilium`` container image as a pod on
each Kubernetes worker node.

Mounting the BPF FS (Optional)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This step is optional but recommended. It allows the Cilium agent to pin BPF
resources to a persistent filesystem to make them persistent across
cilium-agent restarts.  If the BPF filesystem is not mounted in the host
filesystem, then all BPF resources created in the namespace of the pod will be
released when the pod is stopped and restarted. This would result in network
connectivity loss of all locally managed pods when the agent is restarted.
Mounting the BPF filesystem in the host will ensure that the agent can be
restarted without affecting connectivity of any pods.

In order to mount the BPF filesystem, the following command must be run in the
host mount namespace. The command must only be run once during the boot process
of the machine.

::

	mount bpffs /sys/fs/bpf -t bpf

If you are using systemd to manage the kubelet, the easiest way to achieve this
is to add a ``ExecStartPre`` line in the ``/etc/systemd/kubelet.service`` file
as follows.

::

	[Service]
        ExecStartPre=/bin/bash -c ' \\
                if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
                   /bin/mount bpffs /sys/fs/bpf -t bpf; \\
                fi'

.. _k8s_ds:

Installing Cilium using Kubernetes Daemon Sets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Deploying the DaemonSet
~~~~~~~~~~~~~~~~~~~~~~~

Save the following template to a file ``cilium-ds.yaml`` and adjust any
configuration as necessary if default behaviour is not desirable:

::

	apiVersion: extensions/v1beta1
	kind: DaemonSet
	metadata:
	  name: cilium
	spec:
	  template:
	    metadata:
	      labels:
	        k8s-app: cilium
	        kubernetes.io/cluster-service: "true"
	    spec:
	      containers:
	      - image: cilium/cilium:latest
	        imagePullPolicy: Always
	        name: cilium-agent
	        command: [ "/home/with-cni.sh", "--debug", "daemon", "run" ]
	        args:
	          - "-t"
	          - "vxlan"
	          - "--kvstore"
	          - "etcd"
	          - "--kvstore-opt"
	          - "etcd.config=/var/lib/cilium/etcd-config.yml"
	          - "--k8s-kubeconfig-path"
	          - "/var/lib/kubelet/kubeconfig"
	        env:
	          - name: "K8S_NODE_NAME"
	            valueFrom:
	              fieldRef:
	                fieldPath: spec.nodeName
	        volumeMounts:
	          - name: cilium-run
	            mountPath: /var/run/cilium
	          - name: cni-path
	            mountPath: /tmp/cni/bin
	          - name: bpf-maps
	            mountPath: /sys/fs/bpf
	          - name: docker-socket
	            mountPath: /var/run/docker.sock
	            readOnly: true
	          - name: etcd-config
	            mountPath: /var/lib/cilium/etcd-config.yml
	            readOnly: true
	          - name: kubeconfig-path
	            mountPath: /var/lib/kubelet/kubeconfig
	            readOnly: true
	          - name: kubeconfig-cert
	            mountPath: /var/lib/kubernetes/ca.pem
	            readOnly: true
	        securityContext:
	          capabilities:
	            add:
	              - "NET_ADMIN"
	          privileged: true
	      hostNetwork: true
	      volumes:
	        - name: cilium-run
	          hostPath:
	              path: /var/run/cilium
	        - name: cni-path
	          hostPath:
	              path: /opt/cni/bin
	        - name: bpf-maps
	          hostPath:
	              path: /sys/fs/bpf
	        - name: docker-socket
	          hostPath:
	              path: /var/run/docker.sock
	        - name: etcd-config
	          hostPath:
	              path: /var/lib/cilium/etcd-config.yml
	        - name: kubeconfig-path
	          hostPath:
	              path: /var/lib/kubelet/kubeconfig
	        - name: kubeconfig-cert
	          hostPath:
	              path: /var/lib/kubernetes/ca.pem

Deploy Cilium to all nodes using ``kubectl``:

::

   $ kubectl create -f cilium-ds.yaml

While ``kubectl`` deploys the pods, you can monitor the progress and you will
notice the number of ready pods going from 0 to the desired number which will
equals to the number of nodes in the cluster.

::

        $ kubectl get ds
        NAME      DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
        cilium    1         1         0         <none>          3s

As the pods are deployed, the number in the ready column will increase and
eventually reach the desired count. This indicates the progress of deployment.

::

        $ kubectl describe ds cilium
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

::

	$ kubectl get pods
        NAME           READY     STATUS    RESTARTS   AGE
        cilium-2xzqm   1/1       Running   0          41m
        $ kubectl logs cilium-2xzqm
        INFO      _ _ _
        INFO  ___|_| |_|_ _ _____
        INFO |  _| | | | | |     |
        INFO |___|_|_|_|___|_|_|_|
        INFO Cilium 0.8.90 f022e2f Thu, 27 Apr 2017 23:17:56 -0700 go version go1.7.5 linux/amd64
        INFO clang and kernel versions: OK!
        INFO linking environment: OK!
        [...]



Deploying to selected nodes
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To deploy Cilium to only a selected list of nodes, you can add a
``NodeSelector`` to the ``DaemonSet`` like this:

::

	spec:
	  template:
	    spec:
	      nodeSelector:
	        with-network-plugin: cilium

And then label each node where Cilium should be deployed:

::

    kubectl label node worker0 with-network-plugin=cilium
    kubectl label node worker1 with-network-plugin=cilium
    kubectl label node worker2 with-network-plugin=cilium

Removing the cilium daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~

All cilium agents are managed as a DaemonSet which means that deleting
the DaemonSet will automatically stop and remove all pods which run Cilium
on each node:

::

        $ kubectl delete ds cilium

Troubleshooting
~~~~~~~~~~~~~~~

Check the status of the ``DaemonSet`` and verify that all all desired
instances are in "ready" state:

::

        $ kubectl get ds
        NAME      DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
        cilium    1         1         0         <none>          3s

In this example, we see a desired state of 1 with 0 being ready. This indicates
a problem. Let's list all cilium pods by matching on the label
``k8s-app=cilium`` and also sort the list by the restart count of each pod to
identify the failing pods:

::

        $ kubectl get pods --selector k8s-app=cilium --sort-by='.status.containerStatuses[0].restartCount'
        NAME           READY     STATUS             RESTARTS   AGE
        cilium-813gf   0/1       CrashLoopBackOff   2          44s

Pod ``cilium-813gf`` is failing and has already been restarted 2 times. Let's
print the logfile of that pod to investigate the cause:

::

        $ kubectl logs cilium-813gf
        INFO      _ _ _
        INFO  ___|_| |_|_ _ _____
        INFO |  _| | | | | |     |
        INFO |___|_|_|_|___|_|_|_|
        INFO Cilium 0.8.90 f022e2f Thu, 27 Apr 2017 23:17:56 -0700 go version go1.7.5 linux/amd64
        CRIT kernel version: NOT OK: minimal supported kernel version is >= 4.8

In this example, the cause for the failure is a Linux kernel that is not recent
enough.

If the cause for the problem is not apparent or you seek further help, consider
joining on our `slack channel <https://cilium.herokuapp.com>`_ to ask
questions.


Installing Cilium using Docker Compose
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Below is an example of using Docker Compose to deploy the
Cilium agent and the Cilium Docker libnetwork plugin.

Note: for multi-host deployments using a key-value store, you would want to
update this template to point cilium to a central key-value store.

::

  version: '2'
  services:
    cilium:
      container_name: cilium
      image: cilium/cilium:cilium-ubuntu-16-04
      command: cilium-agent --debug -d ${IFACE} -c 127.0.0.1:8500
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
        - /var/run/cilium:/var/run/cilium
        - /run/docker/plugins:/run/docker/plugins
        - /sys/fs/bpf:/sys/fs/bpf
      network_mode: "host"
      cap_add:
        - "NET_ADMIN"
      privileged: true

    cilium_docker:
      container_name: cilium-docker-plugin
      image: cilium/cilium:stable
      command: cilium-docker -D
      volumes:
        - /var/run/cilium:/var/run/cilium
        - /run/docker/plugins:/run/docker/plugins
      network_mode: "host"
      cap_add:
        - "NET_ADMIN"
      privileged: true
      depends_on:
        - cilium


Build + Install From Source
^^^^^^^^^^^^^^^^^^^^^^^^^^^
Installing Cilium from a container is recommmened.  If you need to build / install
Cilium directly on the container Linux node, there are additional required dependencies
beyond a 4.8.0+ Linux kernel:

* clang+LLVM >=3.7.1. Please note that in order to use clang 3.9.x, the kernel version requirement is >= 4.9.17
* iproute2 >= 4.8.0: https://www.kernel.org/pub/linux/utils/net/iproute2/
* (recommended) Linux kernel >= 4.9.17. Use of a 4.9.17 kernel or later will ensure compatibility with clang > 3.9.x

Download the Cilium source code, and run ``make install``.
This will install cilium binaries in your ``bindir``
and all required additional runtime files in ``libdir/cilium``.

Templates for integration into service management systems such as
systemd and upstart can be found in the ``contrib``
directory.

For example:
::

    make install
    sudo cp contrib/upstart/* /etc/init/
    service cilium start


Container Node Network Configuration
------------------------------------

The networking configuration required on your Linux container node
depends on the IP interconnectivity model in use and whether the
deployment requires containers in the cluster to reach or be reached by
resources outside the cluster.  For more details, see the
Architecture Guide's section on :ref:`arch_ip_connectivity` .

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
network (e.g,.
`AWS VPC Route Tables <http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Route_Tables.html>`_
or `GCE Routes <https://cloud.google.com/compute/docs/reference/latest/routes>`_ ).   These
APIs can be used to associate each node prefix with the appropriate next hop IP each
time a container node is added to the cluster.

An example using GCE Routes for this is available
`here <https://github.com/cilium/cilium/blob/gce-example/examples/gce/docs/07-network.md>`_ .

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

::

    ip -6 route get `host -t aaaa www.google.com | awk '{print $5}'`
    ping6 www.google.com

If the default route is missing, your VM may not be receiving router
advertisements. In this case, the default route can be added manually:

::

    ip -6 route add default via beef::1

The following tests connectivity from a container to the outside world:

::

    $ sudo docker run --rm -ti --net cilium -l client cilium/demo-client ping6 www.google.com
    PING www.google.com(zrh04s07-in-x04.1e100.net) 56 data bytes
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=1 ttl=56 time=7.84 ms
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=2 ttl=56 time=8.63 ms
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=3 ttl=56 time=8.83 ms

Note that an appropriate policy must be loaded or policy enforcement will drop
the relevant packets. An example policy can be found in `examples/policy/test/
<https://github.com/cilium/cilium/tree/master/examples/policy/test>`_ which
will allow the above container with the label ``io.cilium`` to be reached from
world scope. To load and test:

::

    $ cilium policy import examples/policy/test/test.policy
    $ cilium policy allowed -s reserved:world -d io.cilium

Configuring Cilium to use a Key-Value Store
-------------------------------------------

Cilium can use both Consul and etcd as a key-value store.   See
:ref:`admin_agent_options` for the command-line options to configure both options.


Container Platform Integrations
-------------------------------

Docker
^^^^^^

Configuring Cilium as a Docker Network Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As described above, the Cilium installation process creates a
``cilium-docker`` which implements the plugin logic.  When launched, the
cilium-docker binary automatically registers itself with the local Docker daemon.

The cilium-docker binary also communicates
with the main Cilium Agent via the agent's UNIX domain
socket (``/var/run/cilium/cilium.sock``), so the plugin binary
must have permissions to send / receive calls to this socket.

Network Creation
~~~~~~~~~~~~~~~~

As isolation and segmentation is enforced based on Docker container labels,
all containers can be attached to a single Docker network (this is the
recommended configuration).
Please note that IPv6 must be enabled on the network as
the IPv6 address is also the unique identifier for each container:

::

    $ docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium
    $ docker run --net cilium hello-world

Running a Container
~~~~~~~~~~~~~~~~~~~

Any container attached to a Cilium managed network will automatically have networking
managed by Cilium.  For example:

::

    $ docker run --net cilium hello-world

Kubernetes
^^^^^^^^^^

API Server Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

With kubernetes there is only one implicit logical network for pods, so
rather than creating a network, you start the
kubernetes API server with a prefix matching your Cilium prefix (e.g.,
``--service-cluster-ip-range="f00d:1::/112"``)

**Important note**: The `service-cluster-ip-range` is currently limited to a single address
family. This means that unless you are running Cilium with `--disable-ipv4`, the
`service-cluster-ip-range` must be set to an IPv4 range. This should get resolved once
Kubernetes starts supporting multiple IP addresses for a single pod.

TODO:  do we need to recommend installing security policies that enable kube-dns, etc?

Container Node / Kubelet Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enabling the Cilium and Loopback CNI Plugins
````````````````````````````````````````````
Create cni configuration file to tell the kubelet
that it should use the cilium cni plugin:



::

  sudo mkdir -p /etc/cni/net.d
  sudo sh -c 'echo "{
      "name": "cilium",
      "type": "cilium-cni",
      "mtu": 1450
  }
  " > /etc/cni/net.d/10-cilium-cni.conf'

Since kubernetes ``v1.3.5`` the user needs to install the ``loopback`` cni plugin:

::

   sudo mkdir -p /opt/cni
   wget https://storage.googleapis.com/kubernetes-release/network-plugins/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
   sudo tar -xvf cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz -C /opt/cni

Make two changes to the kubelet systemd unit file:

 *  include an [ExecPre] block to mount the BPF filesystem: ``ExecPre=/bin/mount bpffs /sys/fs/bpf -t bpf``
 *  include a flag instructing the kubelet to use CNI plugins: ``--network-plugin=cni``

An example systemd file with these changes is below:

::

	sudo sh -c 'cat > /etc/systemd/system/kubelet.service <<"EOF"
	[Unit]
	Description=Kubernetes Kubelet
	Documentation=https://github.com/GoogleCloudPlatform/kubernetes
	After=docker.service
	Requires=docker.service

	[Service]
	ExecPre=/bin/mount bpffs /sys/fs/bpf -t bpf
	ExecStart=/usr/bin/kubelet \
	  --allow-privileged=true \
	  --api-servers=https://172.16.0.10:6443,https://172.16.0.11:6443,https://172.16.0.12:6443 \
	  --cloud-provider= \
	  --make-iptables-util-chains=false \
	  --cluster-dns=10.32.0.10 \
	  --cluster-domain=cluster.local \
	  --container-runtime=docker \
	  --docker=unix:///var/run/docker.sock \
	  --network-plugin=cni \
	  --kubeconfig=/var/lib/kubelet/kubeconfig \
	  --serialize-image-pulls=false \
	  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \
	  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \
	  --v=2

	Restart=on-failure
	RestartSec=5

	[Install]
	WantedBy=multi-user.target
	EOF'


Disabling Kube-proxy
````````````````````

Additionally, you should disable the local kube-proxy running on each container
Node, as Cilium performs this function itself.

TODO:  include command for disabling kube-proxy


.. _admin_agent_options:

Cilium Agent Command Line Options
---------------------------------

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
| enable-policy       | Enable policy enforcement            | false                |
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

Cilium CLI Commands
-------------------

TODO: cover Cilium CLI commands

Troubleshooting
---------------

TODO: troubleshooting
 * describe locations of log files
 * describe tools used for debugging

