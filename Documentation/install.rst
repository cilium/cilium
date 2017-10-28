.. _install_guide:

##################
Installation Guide
##################

This document describes how to install and configure Cilium in different
deployment modes. It focuses on a full deployment of Cilium within a datacenter
or public cloud. If you are just looking for a simple way to experiment, we
highly recommend trying out the :ref:`gs_guide` instead.

This guide assumes that you have read the :ref:`arch_guide` which explains all
the components and concepts.

.. _admin_system_reqs:

*******************
System Requirements
*******************

Before installing Cilium. Please ensure that your system is meeting the minimal
requirements to run Cilium. Most modern Linux distributions will automatically
meet the requirements.

Summary
=======

When running Cilium using the container image ``cilium/cilium``, these are
the requirements your system has to fulfill:

- `Linux kernel`_ >= 4.8 (>= 4.9.17 LTS recommended)
- Key-Value store (see :ref:`req_kvstore` section for version details)

The following additional dependencies are **only** required if you choose
**not** to use the ``cilium/cilium`` container image and want to run Cilium as
a native process on your host:

- `clang+LLVM`_ >=3.7.1
- iproute2_ >= 4.8.0

Linux Distribution Compatibility Matrix
=======================================

The following table lists Linux distributions versions which are known to work
well with Cilium.

===================== ====================
Distribution          Minimal Version
===================== ====================
CoreOS_               stable (>= 1298.5.0)
Debian_               >= 9 Stretch
`Fedora Atomic/Core`_ >= 25
LinuxKit_             all
Ubuntu_               >= 16.04.2, >= 16.10
===================== ====================

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
============

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
===============

Cilium uses a distributed Key-Value store to manage and distribute security
identities across all cluster nodes. The following Key-Value stores are
currently supported:

- etcd >= 3.1.0
- consul >= 0.6.4

See section :ref:`install_kvstore` for details on how to configure the
`cilium-agent` to use a Key-Value store.

clang+LLVM
==========


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
========

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

*****************************
Kubernetes Installation Guide
*****************************

This section describes how to install and run Cilium on Kubernetes. The
deployment method we are using is called DaemonSet_ which is the easiest way to deploy
Cilium in a Kubernetes environment. It will request Kubernetes to automatically
deploy and run a ``cilium/cilium`` container image as a pod on all Kubernetes
worker nodes.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on `Slack channel`_.

Quick Guide
===========

If you know what you are doing, then the following quick instructions get you
started in the shortest time possible. If you require additional details or are
looking to customize the installation then read the remaining sections of this
chapter.

1. Mount the BPF filesystem on all k8s worker nodes. There are many ways to
   achieve this, see section :ref:`admin_mount_bpffs` for more details.

.. code:: bash

	mount bpffs /sys/fs/bpf -t bpf

2. Download the DaemonSet_ template ``cilium.yaml`` and specify the etcd address:

.. parsed-literal::

    $ wget \ |SCM_WEB|\/examples/kubernetes/cilium.yaml
    $ vim cilium.yaml
    [adjust the etcd address]

**Optional:** If you want to adjust the MTU of the pods, define the ``MTU`` environment
variable in the ``env`` section:

.. code:: bash

    env:
      - name: "MTU"
        value: "8950"

3. Deploy ``cilium`` with your local changes

.. code:: bash

    $ kubectl create -f ./cilium.yaml
    clusterrole "cilium" created
    serviceaccount "cilium" created
    clusterrolebinding "cilium" created
    configmap "cilium-config" created
    secret "cilium-etcd-secrets" created
    daemonset "cilium" created

    $ kubectl get ds --namespace kube-system
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          1         1         1         <none>          2m

You have cilium deployed in your cluster and ready to use.

.. _admin_mount_bpffs:

Detailed Step by Step Instructions
==================================

Mounting the BPF FS (Optional)
------------------------------

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
mountd systemd service on all hosts:

.. literalinclude:: ../contrib/systemd/sys-fs-bpf.mount

CNI Configuation
----------------

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

The CNI installation can be configured with environment variables. These
environment variables can be specified in the DaemonSet file like this:

.. code:: bash

    env:
      - name: "MTU"
        value: "8950"

The following variables are supported:

+---------------------+--------------------------------------+------------------------+
| Option              | Description                          | Default                |
+---------------------+--------------------------------------+------------------------+
| MTU                 | Pod MTU to be configured             | 1450                   |
+---------------------+--------------------------------------+------------------------+
| HOST_PREFIX         | Path prefix of all host mounts       | /host                  |
+---------------------+--------------------------------------+------------------------+
| CNI_DIR             | Path to mounted CNI directory        | ${HOST_PREFIX}/opt/cni |
+---------------------+--------------------------------------+------------------------+
| CNI_CONF_NAME       | Name of configuration file           | 10-cilium.conf         |
+---------------------+--------------------------------------+------------------------+

If you want to further adjust the CNI configuration you may do so by creating
the CNI configuration ``/etc/cni/net.d/10-cilium.conf`` manually:

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

.. _ds_deploy:

Deploying the DaemonSet
-----------------------

.. parsed-literal::

    $ wget \ |SCM_WEB|\/examples/kubernetes/cilium.yaml
    $ vim cilium.yaml
    [adjust the etcd address]

After configuring the ``cilium`` ConfigMap_ it is time to deploy it using
``kubectl``:

.. code:: bash

    $ kubectl create -f cilium.yaml

Kubernetes will deploy the ``cilium`` DaemonSet_ as a pod in the ``kube-system``
namespace on all worker nodes. This operation is performed in the background.
Run the following command to check the progress of the deployment:

.. code:: bash

    $ kubectl --namespace kube-system get ds
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          4         4         4         <none>          2m


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

        $ kubectl --namespace kube-system logs cilium-2xzqm
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

To deploy Cilium only to a selected list of worker nodes, you can add a
NodeSelector_ to the ``cilium.yaml`` file like this:

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
----------------------------

In case pods were already running before the Cilium DaemonSet was deployed,
these pods will still be connected using the previous networking plugin
according to the CNI configuration. A typical example for this is the
``kube-dns`` service which runs in the ``kube-system`` namespace by default.

A simple way to change networking for such existing pods is to rely on the fact
that Kubernetes automatically restarts pods in a Deployment if they are
deleted, so we can simply delete the original kube-dns pod and the replacement
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
        kube-addon-manager-minikube   1/1       Running       0          59m
        kube-dns-268032401-j0vml      3/3       Running       0          9s
        kube-dns-268032401-t57r2      3/3       Terminating   0          57m

Removing the cilium daemon
--------------------------

All cilium agents are managed as a DaemonSet_ which means that deleting the
DaemonSet_ will automatically stop and remove all pods which run Cilium on each
worker node:

.. code:: bash

        $ kubectl --namespace kube-system delete ds cilium


Migrating Cilium TPR to CRD
===========================

Prior to Kubernetes 1.7, Cilium Network Policy (CNP) objects were imported as a `Kubernetes ThirdPartyResource (TPRs) <https://kubernetes.io/docs/tasks/access-kubernetes-api/extend-api-third-party-resource/>`_.
In Kubernetes ``>=1.7.0``, TPRs are now deprecated, and will be removed in Kubernetes 1.8. TPRs are  replaced by `Custom Resource Definitions (CRDs) <https://kubernetes.io/docs/concepts/api-extension/custom-resources/#customresourcedefinitions>`_.  Thus, as part of the upgrade process to Kubernetes 1.7, Kubernetes has provided documentation for `migrating TPRs to CRDS <http://cilium.link/migrate-tpr>`_. 

The following instructions document how to migrate CiliumNetworkPolicies existing as TPRs from a Kubernetes cluster which was previously running versions ``< 1.7.0`` to CRDs on a Kubernetes cluster running versions ``>= 1.7.0``. This is meant to correspond to steps 4-6 of the `aforementioned guide <http://cilium.link/migrate-tpr>`_.

Cilium adds the CNP CRD automatically; check to see that the CNP CRD has been added by Cilium:

.. code:: bash

       $ kubectl get customresourcedefinition
       NAME                              KIND
       ciliumnetworkpolicies.cilium.io   CustomResourceDefinition.v1beta1.apiextensions.k8s.io

Save your existing CNPs which were previously added as TPRs:

.. code:: bash

       $ kubectl get ciliumnetworkpolicies --all-namespaces -o yaml > cnps.yaml

Change the version of the Cilium API from v1 to v2 in the YAML file to which you just saved your old CNPs. The Cilium API is versioned to account for the change from TPR to CRD:

.. code:: bash

       $ cp cnps.yaml cnps.yaml.new
       $ # Edit the version
       $ vi cnps.yaml.new
       $ # The diff of the old vs. new YAML file should be similar to the output below.
       $ diff cnps.yaml cnps.yaml.new
       3c3
       < - apiVersion: cilium.io/v1
       ---
       > - apiVersion: cilium.io/v2
       10c10
       <     selfLink: /apis/cilium.io/v1/namespaces/default/ciliumnetworkpolicies/guestbook-web-deprecated
       ---
       >     selfLink: /apis/cilium.io/v2/namespaces/default/ciliumnetworkpolicies/guestbook-web-deprecated

Delete your old CNPs:

.. code:: bash

       $ kubectl delete ciliumnetworkpolicies --all
       $ kubectl delete thirdpartyresource cilium-network-policy.cilium.io

Add the changed CNPs back as CRDs:

.. code:: bash

       $ kubectl create -f cnps.yaml.new

Check that your CNPs are added:

.. code:: bash

       $ kubectl get ciliumnetworkpolicies
       NAME                       KIND
       guestbook-web-deprecated   CiliumNetworkPolicy.v2.cilium.io
       multi-rules-deprecated     CiliumNetworkPolicy.v2.cilium.io   Policy to test multiple rules in a single file   2 item(s)

Now if you try to create a CNP as a TPR, you will get an error:

.. code:: bash

       $ Error from server (BadRequest): error when creating "cilium-tpr.yaml": the API version in the data (cilium.io/v1) does not match the expected API version (cilium.io/v2)

Troubleshooting
===============

See the section :ref:`troubleshooting_k8s` for Kubernetes specific instructions
on how to troubleshoot a setup.

.. _admin_install_docker_compose:

*********************************
Docker Compose Installation Guide
*********************************

This section describes how to install & run the Cilium container image using
Docker compose.

Note: for multi-host deployments using a key-value store, you would want to
update this template to point cilium to a central key-value store.

.. parsed-literal::

    $ wget \ |SCM_WEB|\/examples/docker-compose/docker-compose.yml
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

.. _coreos_gs_guide:

*************************
CoreOS Installation Guide
*************************

This document serves as a guide to get Cilium up-and-running on CoreOS.

If you haven't read the :ref:`intro` yet, we encourage you to do that first.

For an introduction about how to setup Kubernetes with CoreOS, we recommend
following along with the `Core OS guide <https://coreos.com/kubernetes/docs/latest/getting-started.html>`_.
The CoreOS guide serves as a reference to setting up Kubernetes components (e.g., kube-apiserver, kube-scheduler, certificates, etc.), while this page focuses specifically on the modifications needed to get Cilium functioning with CoreOS.

The best way to get help if you get stuck is to ask a question on the `Cilium 
Slack channel <https://cilium.herokuapp.com>`_. With Cilium contributors
across the globe, there is almost always someone available to help.


Minimum Requirements
====================

* Make sure you understand the various `deployment options <https://coreos.com/kubernetes/docs/latest/getting-started.html#deployment-options>`_.
* *etcd*
    * ``etcd`` must be at version ``>= 3.1.0``. To set up etcd, follow `the CoreOS instructions for setting up an etcd cluster <https://coreos.com/kubernetes/docs/latest/getting-started.html#deploy-etcd-cluster>`_.
* *kubectl*
    * It is also required that you install ``kubectl`` version ``>= 1.6.4`` as described in the `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_.

Setup Master Nodes
==================

Step 1: Create TLS Assets
-------------------------
Follow the `CoreOS instructions for creating TLS assets on master nodes <https://coreos.com/kubernetes/docs/latest/getting-started.html#generate-kubernetes-tls-assets>`_ and `install the TLS assets needed for the master nodes <https://coreos.com/kubernetes/docs/latest/deploy-master.html#tls-assets>`_ for secure communication with the kube-apiserver.


Step 2: Setup Kubelet
---------------------

On CoreOS, Kubelet (the Kubernetes agent that runs on each node, more info `here <https://kubernetes.io/docs/admin/kubelet/>`_) runs as a container. In order to securely communicate with the API server, kubelet uses the TLS assets we generated as part of Step 1.

Master nodes are usually not scheduled to run workloads, so we provide the ``-register-schedulable=false`` in the example YAML excerpt below. This ensures that workloads are only scheduled on worker nodes.

Since we are setting up Kubelet to use Cilium, we want to configure its networking to utilize CNI (Container Networking Interface). This ensures that each pod that is created can communicate with one another within the cluster with Cilium networking configured.

* Replace ${ADVERTISE_IP} with this node's publicly routable IP.
* Replace ${DNS_SERVICE_IP}. For more information about what this IP is, refer to `the CoreOS documentation for Kubernetes deployment options <https://coreos.com/kubernetes/docs/latest/getting-started.html#deployment-options>`_. 
* Replace ${KUBE_VERSION} with a version  ``>= 1.6.4``.
* Cilium-specific configuration    

    * Mount the CNI configuration directory you created in step 1 so Kubelet can pick up the CNI configuration from the host filesystem:

         ::

             --volume etc-cni,kind=host,source=/etc/cni/net.d \
             --mount volume=etc-cni,target=/etc/cni/net.d

    * Mount the directory where CNI plugins are installed:

        ::

             --volume cni-bin,kind=host,source=/opt/cni/bin \
             --mount volume=cni-bin,target=/opt/cni/bin

    * `Mount the BPF filesystem <http://docs.cilium.io/en/latest/admin/#mounting-the-bpf-fs>`_ so that the information stored there persists across Cilium restarts:

        ::
             
             ExecStartPre=/bin/bash -c ' \\
               if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
                 /bin/mount bpffs /sys/fs/bpf -t bpf; \\
               fi'

    * Also ensure that you specify that the network plugin is CNI: 

        ::  

             --network-plugin=cni

    * Specify the CNI directory to correspond to the mount you provided earlier where the CNI configuration is located:
    
        ::

             --cni-conf-dir=/etc/cni/net.d

`/etc/systemd/system/kubelet.service`

:: 

    [Service]
    Environment=KUBELET_IMAGE_TAG=v'"${KUBE_VERSION}"'_coreos.0
    Environment="RKT_RUN_ARGS=--uuid-file-save=/var/run/kubelet-pod.uuid \
      --volume var-log,kind=host,source=/var/log \
      --mount volume=var-log,target=/var/log \
      --volume dns,kind=host,source=/etc/resolv.conf \
      --mount volume=dns,target=/etc/resolv.conf \
      --volume cni-bin,kind=host,source=/opt/cni/bin \
      --mount volume=cni-bin,target=/opt/cni/bin \
      --volume etc-cni,kind=host,source=/etc/cni/net.d \
      --mount volume=etc-cni,target=/etc/cni/net.d"
    ExecStartPre=/usr/bin/mkdir -p /etc/cni/net.d
    ExecStartPre=/bin/bash -c ' \\
      if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
        /bin/mount bpffs /sys/fs/bpf -t bpf; \\
      fi'
    ExecStartPre=/usr/bin/mkdir -p /opt/cni/bin
    ExecStartPre=/usr/bin/mkdir -p /etc/kubernetes/manifests
    ExecStartPre=/usr/bin/mkdir -p /var/log/containers
    ExecStartPre=-/usr/bin/rkt rm --uuid-file=/var/run/kubelet-pod.uuid
    ExecStart=/usr/lib/coreos/kubelet-wrapper \
      --api-servers=http://127.0.0.1:8080 \
      --register-schedulable=false \
      --cni-conf-dir=/etc/cni/net.d \
      --network-plugin=cni \
      --container-runtime=docker \
      --allow-privileged=true \
      --pod-manifest-path=/etc/kubernetes/manifests \
      --hostname-override=${ADVERTISE_IP} \
      --cluster-dns=${DNS_SERVICE_IP} \
      --cluster-domain=cluster.local
    ExecStop=-/usr/bin/rkt stop --uuid-file=/var/run/kubelet-pod.uuid
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target


Step 3: Setup kube-apiserver on the master nodes
------------------------------------------------

Follow the `CoreOS instructions for setting up the API server <https://coreos.com/kubernetes/docs/latest/deploy-master.html#set-up-the-kube-apiserver-pod>`_. 

Make sure that you set the version of the kube-apiserver to whatever version you are using for the Kubelet as well, e.g.:

::

    quay.io/coreos/hyperkube:v${KUBE_VERSION}_coreos.0

Step 4: Setup kube-controller-manager on the master nodes
---------------------------------------------------------

Per the `CoreOS guide <https://coreos.com/kubernetes/docs/latest/deploy-master.html#set-up-the-kube-controller-manager-pod>`_, "the controller manager is responsible for reconciling any required actions based on changes to `Replication Controllers <https://coreos.com/kubernetes/docs/latest/replication-controller.html>`_. For example, if you increased the replica count, the controller manager would generate a scale up event, which would cause a new Pod to get scheduled in the cluster. The controller manager communicates with the API to submit these events.

Create `/etc/kubernetes/manifests/kube-controller-manager.yaml`. It will use the TLS certificate placed on disk earlier."

* Add ``--allocate-node-cidrs`` to ensure that the kube-controller-manager allocates unique pod CIDR blocks for each node in the cluster.
* Substitute ${CLUSTER_CIDR} with the CIDR range for pods in your cluster.
* Substitute ${SERVICE_CLUSTER_IP_RANGE} with the IP range used for service IPs in your cluster.
* Set NODE_CIDR_MASK_SIZE to a size that you want for each CIDR block on each node.

`/etc/kubernetes/manifests/kube-controller-manager.yaml.`

:: 

    apiVersion: v1
    kind: Pod
    metadata:
      name: kube-controller-manager
      namespace: kube-system
    spec:
      hostNetwork: true
      containers:
      - name: kube-controller-manager
        image: quay.io/coreos/hyperkube:v'"${KUBE_VERSION}"'_coreos.0
        command:
        - /hyperkube
        - controller-manager
        - --allocate-node-cidrs
        - --cluster-cidr=${CLUSTER_CIDR}
        - --service-cluster-ip-range=${SERVICE_CLUSTER_IP_RANGE}
        - --node-cidr-mask-size=${NODE_CIDR_MASK_SIZE}
        - --master=http://127.0.0.1:8080
        - --leader-elect=true
        - --service-account-private-key-file=/etc/kubernetes/ssl/apiserver-key.pem
        - --root-ca-file=/etc/kubernetes/ssl/ca.pem
        resources:
          requests:
            cpu: 200m
        livenessProbe:
          httpGet:
            host: 127.0.0.1
            path: /healthz
            port: 10252
          initialDelaySeconds: 15
          timeoutSeconds: 15
        volumeMounts:
        - mountPath: /etc/kubernetes/ssl
          name: ssl-certs-kubernetes
          readOnly: true
        - mountPath: /etc/ssl/certs
          name: ssl-certs-host
          readOnly: true
      volumes:
      - hostPath:
          path: /etc/kubernetes/ssl
        name: ssl-certs-kubernetes
      - hostPath:
          path: /usr/share/ca-certificates
        name: ssl-certs-host


Step 5: Setup kube-scheduler on the master nodes
------------------------------------------------

Cilium has no special requirements for setting up the kube-scheduler on master nodes. Follow the `CoreOS instructions for setting up kube-scheduler <https://coreos.com/kubernetes/docs/latest/deploy-master.html#set-up-the-kube-scheduler-pod>`_.

Make sure that you set the version of the kube-apiserver to whatever version you are using for the Kubelet as well, e.g.:

::

    quay.io/coreos/hyperkube:v${KUBE_VERSION}_coreos.0

Step 6: Setup kube-proxy on master nodes
----------------------------------------

The next step is to setup kube-proxy as a static pod on all master nodes.
Create the file ``/etc/kubernetes/manifests/kube-proxy.yaml`` and substitute
the following variables:

* ``${CLUSTER_CIDR}`` with the CIDR range for pods in your cluster.
* ``${KUBE_VERSION}`` with a version  ``>= 1.6.4``.

::

    apiVersion: v1
    kind: Pod
    metadata:
      name: kube-proxy
      namespace: kube-system
      annotations:
        rkt.alpha.kubernetes.io/stage1-name-override: coreos.com/rkt/stage1-fly
    spec:
      hostNetwork: true
      containers:
      - name: kube-proxy
        image: quay.io/coreos/hyperkube:v'"${KUBE_VERSION}"'_coreos.0
        command:
        - /hyperkube
        - proxy
        - --master=http://127.0.0.1:8080
        - --cluster-cidr=${CLUSTER_CIDR}
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /etc/ssl/certs
          name: ssl-certs-host
          readOnly: true
        - mountPath: /var/run/dbus
          name: dbus
          readOnly: false
      volumes:
      - hostPath:
          path: /usr/share/ca-certificates
        name: ssl-certs-host
      - hostPath:
          path: /var/run/dbus
        name: dbus

Step 7: Start Services on Nodes
-------------------------------

Start kubelet on all nodes:

::

    sudo systemctl start kubelet

To have kubelet start after a reboot, run:

::

    sudo systemctl enable kubelet

Step 8: Health Check of Kubernetes Services
-------------------------------------------

Follow `the CoreOS instructions to health check Kubernetes services <https://coreos.com/kubernetes/docs/latest/deploy-master.html#basic-health-checks>`_.


Step 9: Setup Kubectl to Communicate With Your Cluster
------------------------------------------------------

Follow `the CoreOS instructions to download kubectl <https://coreos.com/kubernetes/docs/latest/configure-kubectl.html#download-the-kubectl-executable>`_.

* Replace ${MASTER_HOST} with the master node address or name used in previous steps
* Replace ${CA_CERT} with the absolute path to the ca.pem created in previous steps
* Replace ${ADMIN_KEY} with the absolute path to the admin-key.pem created in previous steps
* Replace ${ADMIN_CERT} with the absolute path to the admin.pem created in previous steps

:: 

    kubectl config set-cluster default-cluster --server=https://${MASTER_IP} --certificate-authority=${CA_CERT} --embed-certs=true 
    kubectl config set-credentials default-admin --certificate-authority=${CA_CERT} --client-key=${ADMIN_KEY} --client-certificate=${ADMIN_CERT} --embed-certs=true
    kubectl config set-context default-system --cluster=default-cluster --user=default-admin 
    kubectl config use-context default-system 

This will populate the Kubeconfig file with the contents of the certificates, which is needed for Cilium to authenticate against the Kubernetes API when it is launched in the next step.

Alternatively, you can run the above commands without ``--embed-certs=true``, and then mount the paths to the certificates and keys from the host filesystem in `cilium.yaml`.

Follow `the CoreOS instructions to validate that kubectl has been configured correctly <https://coreos.com/kubernetes/docs/latest/configure-kubectl.html#verify-kubectl-configuration-and-connection>`_.


.. _cilium-daemonset-deployment:

Step 10: Deploy Cilium DaemonSet
--------------------------------

* Follow the instructions for :ref:`ds_deploy`. We recommend using the etcd cluster you have set up as the key-value store for Cilium.

Setup Worker Nodes
==================

Step 1: Create TLS Assets
-------------------------

Cilium has no special requirements for setting up the TLS assets on worker nodes. Follow the `CoreOS instructions for creating TLS assets on worker nodes <https://coreos.com/kubernetes/docs/latest/deploy-workers.html#tls-assets>`_ for secure communication with the ``kube-apiserver``.

Step 2: Setup Kubelet
---------------------

On CoreOS, Kubelet (the Kubernetes agent that runs on each node, more info `here <https://kubernetes.io/docs/admin/kubelet/>`_) runs as a container. In order to securely communicate with the API server, kubelet uses the TLS assets we generated as part of Step 1.

Since we are setting up Kubelet to use Cilium, we want to configure its networking to utilize CNI (Container Networking Interface). This ensures that each pod that is created can communicate with one another within the cluster with Cilium networking configured.

* Replace ${MASTER_HOST}
* Replace ${ADVERTISE_IP} with this node's publicly routable IP.
* Replace ${DNS_SERVICE_IP}. For more information about what this IP is, refer to `the CoreOS documentation for Kubernetes deployment options <https://coreos.com/kubernetes/docs/latest/getting-started.html#deployment-options>`_. 
* Replace ${KUBE_VERSION} with a version  ``>= 1.6.4``.
* Cilium-specific configuration

    * Mount the CNI configuration directory you created in step 1 so Kubelet can pick up the CNI configuration from the host filesystem:

        ::

            --volume etc-cni,kind=host,source=/etc/cni/net.d \
            --mount volume=etc-cni,target=/etc/cni/net.d

    * Mount the directory where CNI plugins are installed:

        ::

            --volume cni-bin,kind=host,source=/opt/cni/bin \
            --mount volume=cni-bin,target=/opt/cni/bin 

    * `Mount the BPF filesystem <http://docs.cilium.io/en/latest/admin/#mounting-the-bpf-fs>`_ so that the information stored there persists across Cilium restarts:

        ::  

            ExecStartPre=/bin/bash -c ' \\
              if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
                /bin/mount bpffs /sys/fs/bpf -t bpf; \\
              fi'

    * Also ensure that you specify that the network plugin is CNI:

        ::

            --network-plugin=cni

    * Specify the CNI directory to correspond to the mount you provided earlier where the CNI configuration is located:

        ::

            --cni-conf-dir=/etc/cni/net.d

`/etc/systemd/system/kubelet.service`
:: 

     [Service]
     Environment=KUBELET_IMAGE_TAG=v'"${KUBE_VERSION}"'_coreos.0
     Environment="RKT_RUN_ARGS=--uuid-file-save=/var/run/kubelet-pod.uuid \
      --volume var-log,kind=host,source=/var/log \
      --mount volume=var-log,target=/var/log \
      --volume dns,kind=host,source=/etc/resolv.conf \
      --mount volume=dns,target=/etc/resolv.conf \
      --volume cni-bin,kind=host,source=/opt/cni/bin \
      --mount volume=cni-bin,target=/opt/cni/bin \
      --volume etc-cni,kind=host,source=/etc/cni/net.d \
      --mount volume=etc-cni,target=/etc/cni/net.d"
     ExecStartPre=/bin/bash -c ' \
       if [[ $(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \
         /bin/mount bpffs /sys/fs/bpf -t bpf; \
       fi'
     ExecStartPre=/usr/bin/mkdir -p /etc/cni/net.d
     ExecStartPre=/usr/bin/mkdir -p /opt/cni/bin
     ExecStartPre=/usr/bin/mkdir -p /etc/kubernetes/manifests
     ExecStartPre=/usr/bin/mkdir -p /var/log/containers
     ExecStartPre=-/usr/bin/rkt rm --uuid-file=/var/run/kubelet-pod.uuid
     ExecStart=/usr/lib/coreos/kubelet-wrapper \
      --api-servers=https://{MASTER_HOST} \
      --register-node=true \
      --cni-conf-dir=/etc/cni/net.d \
      --network-plugin=cni \
      --container-runtime=docker \
      --allow-privileged=true \
      --pod-manifest-path=/etc/kubernetes/manifests \
      --hostname-override=${ADVERTISE_IP} \
      --cluster-dns=${DNS_SERVICE_IP} \
      --kubeconfig=/etc/kubernetes/worker-kubeconfig.yaml \
      --tls-cert-file=/etc/kubernetes/ssl/worker.pem \
      --tls-private-key-file=/etc/kubernetes/ssl/worker-key.pem \
      --cluster-domain=cluster.local
     ExecStop=-/usr/bin/rkt stop --uuid-file=/var/run/kubelet-pod.uuid
     Restart=always
     RestartSec=10

     [Install]
     WantedBy=multi-user.target

Step 3: Setup kube-proxy on worker nodes
----------------------------------------

The next step is to setup kube-proxy as a static pod on all worker nodes.
Create the file ``/etc/kubernetes/manifests/kube-proxy.yaml`` and substitute
the following variables:

* ``${KUBE_VERSION}`` with a version  ``>= 1.6.4``.
* ``${MASTER_HOST}`` with the IP of the master node.
* ``${CLUSTER_CIDR}`` with the CIDR range for pods in your cluster.

::

    apiVersion: v1
    kind: Pod
    metadata:
      name: kube-proxy
      namespace: kube-system
      annotations:
        rkt.alpha.kubernetes.io/stage1-name-override: coreos.com/rkt/stage1-fly
    spec:
      hostNetwork: true
      containers:
      - name: kube-proxy
        image: quay.io/coreos/hyperkube:v'"${KUBE_VERSION}"'_coreos.0
        command:
        - /hyperkube
        - proxy
        - --master=${MASTER_HOST}
        - --cluster-cidr=${CLUSTER_CIDR}
        - --kubeconfig=/etc/kubernetes/worker-kubeconfig.yaml
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /etc/ssl/certs
          name: "ssl-certs"
        - mountPath: /etc/kubernetes/worker-kubeconfig.yaml
          name: "kubeconfig"
          readOnly: true
        - mountPath: /etc/kubernetes/ssl
          name: "etc-kube-ssl"
          readOnly: true
        - mountPath: /var/run/dbus
          name: dbus
          readOnly: false
      volumes:
      - name: "ssl-certs"
        hostPath:
          path: "/usr/share/ca-certificates"
      - name: "kubeconfig"
        hostPath:
          path: "/etc/kubernetes/worker-kubeconfig.yaml"
      - name: "etc-kube-ssl"
        hostPath:
          path: "/etc/kubernetes/ssl"
      - hostPath:
          path: /var/run/dbus
        name: dbus

Step 4: Setup Worker kubeconfig
-------------------------------

Cilium has no special requirements for setting up the ``kubeconfig`` for ``kubelet`` on worker nodes. Please follow `the CoreOS instructions to setup the worker-kubeconfig <https://coreos.com/kubernetes/docs/latest/deploy-workers.html#set-up-kubeconfig>`_.

Step 5: Start Services
----------------------

Start kubelet on all nodes:

::

    sudo systemctl start kubelet

To have kubelet start after a reboot, run:

::
 
    sudo systemctl enable kubelet

Step 6: Make Sure Cilium Runs On Worker Nodes
---------------------------------------------

When we deployed Cilium as part of :ref:`cilium-daemonset-deployment`, the Daemon Set expects the Kubeconfig to be located at the same location on each node in the cluster. So, you need to make sure that the location and contents of the kubeconfig for the worker node is the same as that which Cilium is using on the master nodes, e.g., ``~/.kube/config``.

Step 7: Setup kubectl and deploy add-ons
----------------------------------------

Follow `the CoreOS instructions for setting up kube-dns and kube-dashboard <https://coreos.com/kubernetes/docs/latest/deploy-addons.html>`_.

.. _admin_install_source:

*************************
Installation From Source
*************************

If for some reason you do not want to run Cilium as a container image.
Installing it from source is possible as well. It does come with additional
dependencies described in :ref:`admin_system_reqs`.

0. Requirements:

Install go-bindata:

.. code:: bash

   $ go get -u github.com/jteeuwen/go-bindata/...

Add $GOPATH/bin to your $PATH:

.. code:: bash

   $ # To add $GOPATH/bin in your $PATH run
   $ export PATH=$GOPATH/bin:$PATH

You can also add it in your ``~/.bashrc`` file:

.. code:: bash

   if [ -d $GOPATH/bin ]; then
       export PATH=$PATH:$GOPATH/bin
   fi

1. Download & extract the latest Cilium release from the ReleasesPage_

.. _ReleasesPage: https://github.com/cilium/cilium/releases

.. code:: bash

   $ go get -d github.com/cilium/cilium
   $ cd $GOPATH/src/github.com/cilium/cilium

2. Build & install the Cilium binaries to ``bindir``

.. code:: bash

   $ git checkout v0.11
   $ # We are pointing to $GOPATH/bin as well since it's where go-bindata is
   $ # installed
   $ make
   $ sudo make install

3. Optional: Install upstart/systemd init files:

.. code:: bash

    sudo cp contrib/upstart/* /etc/init/
    service cilium start

    sudo cp contrib/systemd/*.service /lib/systemd/system
    sudo cp contrib/systemd/sys-fs-bpf.mount /lib/systemd/system
    sudo mkdir -p /etc/sysconfig/cilium && cp contrib/systemd/cilium /etc/sysconfig/cilium
    service cilium start

***********************
Agent Command Reference
***********************

.. _admin_agent_options:

Command Line Options
====================

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
|                     | (consul, etcd)                       |                      |
+---------------------+--------------------------------------+----------------------+
| kvstore-opt         | Etcd:                                |                      |
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

.. _install_kvstore:

Key-Value Store
===============

+---------------------+--------------------------------------+----------------------+
| Option              | Description                          | Default              |
+---------------------+--------------------------------------+----------------------+
| --kvstore TYPE      | Key Value Store Type:                |                      |
|                     | (consul, etcd)                       |                      |
+---------------------+--------------------------------------+----------------------+
| --kvstore-opt OPTS  |                                      |                      |
+---------------------+--------------------------------------+----------------------+

consul
------

When using consul, the consul agent address needs to be provided with the
``consul.address``:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| consul.address      | Address | Address of consul agent                           |
+---------------------+---------+---------------------------------------------------+

etcd
----

When using etcd, one of the following options need to be provided to configure the
etcd endpoints:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| etcd.address        | Address | Address of etcd endpoint                          |
+---------------------+---------+---------------------------------------------------+
| etcd.config         | Path    | Path to an etcd configuration file.               |
+---------------------+---------+---------------------------------------------------+

Example of the etcd configuration file:

.. code:: yaml

    ---
    endpoints:
    - https://192.168.0.1:2379
    - https://192.168.0.2:2379
    ca-file: '/var/lib/cilium/etcd-ca.pem'
    # In case you want client to server authentication
    key-file: '/var/lib/cilium/etcd-client.key'
    cert-file: '/var/lib/cilium/etcd-client.crt'


.. _Slack channel: https://cilium.herokuapp.com
.. _DaemonSet: https://kubernetes.io/docs/admin/daemons/
.. _ConfigMap: https://kubernetes.io/docs/tasks/configure-pod-container/configmap/
.. _NodeSelector: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
.. _RBAC: https://kubernetes.io/docs/admin/authorization/rbac/
.. _CNI: https://github.com/containernetworking/cni
.. _Volumes: https://kubernetes.io/docs/tasks/configure-pod-container/configure-volume-storage/

.. _iproute2: https://www.kernel.org/pub/linux/utils/net/iproute2/
.. _llvm: http://releases.llvm.org/
.. _Linux kernel: https://www.kernel.org/
