.. _admin_install_daemonset:

******************
Installation Guide
******************

.. note:: This is the detailed installation guide aimed at production
          installations. If you are looking to get started quickly, the
          :ref:`gs_minikube` or the :ref:`k8s_quick` guide may be better
          options.

This section describes how to install and run Cilium on Kubernetes. The
deployment method we are using is called `DaemonSet` which is the easiest way to
deploy Cilium in a Kubernetes environment. It will request Kubernetes to
automatically deploy and run a ``cilium/cilium`` container image as a pod on
all Kubernetes worker nodes.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on `Slack channel`.  See
the :ref:`k8scompatibility` section for kubernetes API version compatibility.

Kubernetes Requirements
=======================

Enable automatic node CIDR allocation (Recommended)
---------------------------------------------------

Kubernetes has the capability to automatically allocate and assign per node IP
allocation CIDR. Cilium automatically uses this feature if enabled. This is the
easiest method to handle IP allocation in a Kubernetes cluster. To enable this
feature, simply add the following flag when starting
``kube-controller-manager``:

.. code:: bash

        --allocate-node-cidrs

This option is not required but highly recommended.

Running Kubernetes with CRD Validation (Recommended)
----------------------------------------------------

Custom Resource Validation was introduced in Kubernetes since version ``1.8.0``.
This is still considered an alpha feature in Kubernetes ``1.8.0`` and beta in
Kubernetes ``1.9.0``.

Since Cilium ``v1.0.0-rc3``, Cilium will create, or update in case it exists,
the Cilium Network Policy (CNP) Resource Definition with the embedded
validation schema. This allows the validation of CiliumNetworkPolicy to be done
on the kube-apiserver when the policy is imported with an ability to provide
direct feedback when importing the resource.

To enable this feature, the flag ``--feature-gates=CustomResourceValidation=true``
must be set when starting kube-apiserver. Cilium itself will automatically make
use of this feature and no additional flag is required.

.. note:: In case there is an invalid CNP before updating to Cilium
          ``v1.0.0-rc3``, which contains the validator, the kube-apiserver
          validator will prevent Cilium from updating that invalid CNP with
          Cilium node status. By checking Cilium logs for ``unable to update
          CNP, retrying...``, it is possible to determine which Cilium Network
          Policies are considered invalid after updating to Cilium
          ``v1.0.0-rc3``.

To verify that the CNP resource definition contains the validation schema, run
the following command:

``kubectl get crd ciliumnetworkpolicies.cilium.io -o json``

.. code:: bash

	kubectl get crd ciliumnetworkpolicies.cilium.io -o json | grep -A 12 openAPIV3Schema
            "openAPIV3Schema": {
                "oneOf": [
                    {
                        "required": [
                            "spec"
                        ]
                    },
                    {
                        "required": [
                            "specs"
                        ]
                    }
                ],

In case the user writes a policy that does not conform to the schema, Kubernetes
will return an error, e.g.:

.. code:: bash

	cat <<EOF > ./bad-cnp.yaml
	apiVersion: "cilium.io/v2"
	kind: CiliumNetworkPolicy
	description: "Policy to test multiple rules in a single file"
	metadata:
	  name: my-new-cilium-object
	spec:
	  endpointSelector:
	    matchLabels:
	      app: details
	      track: stable
	      version: v1
	  ingress:
	  - fromEndpoints:
	    - matchLabels:
	        app: reviews
	        track: stable
	        version: v1
	    toPorts:
	    - ports:
	      - port: '65536'
	        protocol: TCP
	      rules:
	        http:
	        - method: GET
	          path: "/health"
	EOF

	kubectl create -f ./bad-cnp.yaml
	...
	spec.ingress.toPorts.ports.port in body should match '^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})$'


In this case, the policy has a port out of the 0-65535 range.

.. _admin_mount_bpffs:

Mounting the BPF FS (Optional)
==============================

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
``/etc/fstab`` and then run ``mount /sys/fs/bpf``. This will cause the
filesystem to be automatically mounted when the node boots.

.. code:: bash

     bpffs			/sys/fs/bpf		bpf	defaults 0 0

If you are using systemd to manage the kubelet, another option is to add a
mountd systemd service on all hosts:

Due to how systemd `mounts
<https://unix.stackexchange.com/questions/283442/systemd-mount-fails-where-setting-doesnt-match-unit-name>`__
filesystems, the mount point path must be reflected in the unit filename.

.. code:: bash

        cat <<EOF | sudo tee /etc/systemd/system/sys-fs-bpf.mount
        [Unit]
        Description=Cilium BPF mounts
        Documentation=http://docs.cilium.io/
        DefaultDependencies=no
        Before=local-fs.target umount.target
        After=swap.target

        [Mount]
        What=bpffs
        Where=/sys/fs/bpf
        Type=bpf

        [Install]
        WantedBy=multi-user.target
        EOF


CNI Configuration
=================

`CNI` - Container Network Interface is the plugin layer used by Kubernetes to
delegate networking configuration. You can find additional information on the
`CNI` project website.

.. note:: Kubernetes `` >= 1.3.5`` requires the ``loopback`` `CNI` plugin to be
          installed on all worker nodes. The binary is typically provided by
          most Kubernetes distributions. See section :ref:`install_cni` for
          instructions on how to install `CNI` in case the ``loopback`` binary
          is not already installed on your worker nodes.

CNI configuration is automatically being taken care of when deploying Cilium
via the provided `DaemonSet`. The script ``cni-install.sh`` is automatically run
via the ``postStart`` mechanism when the ``cilium`` pod is started.

.. note:: In order for the the ``cni-install.sh`` script to work properly, the
          ``kubelet`` task must either be running on the host filesystem of the
          worder node, or the ``/etc/cni/net.d`` and ``/opt/cni/bin``
          directories must be mounted into the container where ``kubelet`` is
          running. This can be achieved with `Volumes` mounts.

The CNI auto installation is performed as follows:

1. The ``/etc/cni/net.d`` and ``/opt/cni/bin`` directories are mounted from the
   host filesystem into the pod where Cilium is running.

2. The file ``/etc/cni/net.d/10-cilium.conf`` is written in case it does not
   exist yet.

3. The binary ``cilium-cni`` is installed to ``/opt/cni/bin``. Any existing
   binary with the name ``cilium-cni`` is overwritten.

.. _install_cni:

Installing CNI and loopback
---------------------------

Since Kubernetes ``v1.3.5`` the ``loopback`` `CNI` plugin must be installed.
There are many ways to install `CNI`, the following is an example:

.. code:: bash

    sudo mkdir -p /opt/cni
    wget https://storage.googleapis.com/kubernetes-release/network-plugins/cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz
    sudo tar -xvf cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz -C /opt/cni
    rm cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz

Adjusting CNI configuration
---------------------------

The CNI installation can be configured with environment variables. These
environment variables can be specified in the `DaemonSet` file like this:

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
=======================

.. tabs::
  .. group-tab:: K8s 1.7

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.7/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.8/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.9/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml
      $ vim cilium.yaml
      [adjust the etcd address]


After configuring the ``cilium`` `ConfigMap` it is time to deploy it using
``kubectl``:

.. code:: bash

    $ kubectl create -f cilium.yaml

Kubernetes will deploy the ``cilium`` `DaemonSet` as a pod in the ``kube-system``
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
---------------------------

To deploy Cilium only to a selected list of worker nodes, you can add a
`NodeSelector` to the ``cilium.yaml`` file like this:

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
============================

In case pods were already running before the Cilium `DaemonSet` was deployed,
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
==========================

All cilium agents are managed as a `DaemonSet` which means that deleting the
`DaemonSet` will automatically stop and remove all pods which run Cilium on each
worker node:

.. code:: bash

        $ kubectl --namespace kube-system delete ds cilium

