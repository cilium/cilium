.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_install_daemonset:
.. _k8s_install_standard:

***************************
Standard Installation Guide
***************************

.. note:: This is the standard installation guide aimed at production
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

Requirements
============

* Kubernetes >= 1.8
* Linux kernel >= 4.8
* etcd >= 3.x or consul >= 0.6.4

See :ref:`admin_system_reqs` for additional details on systems requirements.

Privileged Mode
---------------

This requirement is typically met automatically by Kubernetes installers but we
list it here for completeness.  Kubernetes must allow to run privileged
containers. In the past, this was achieved by passing the flag
``--allow-privileged`` to kubelet. The flag has since been deprecated and is
being replaced by [PodSecurity
policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/).

Preparation
===========

Enable CNI in Kubernetes (Required)
-----------------------------------

`CNI` - Container Network Interface is the plugin layer used by Kubernetes to
delegate networking configuration. CNI must be enabled in your Kubernetes
cluster in order to install Cilium. This is done by passing
``--network-plugin=cni`` to kubelet on all nodes. For more information, see
the `Kubernets CNI network-plugins documentation <https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/>`_.

.. _admin_mount_bpffs:

Mounting the BPF FS
-------------------

This step is optional but recommended. It allows the ``cilium-agent`` to pin
BPF resources to a persistent filesystem and make them persistent across
restarts of the agent. If the BPF filesystem is not mounted in the host
filesystem, Cilium will automatically mount the filesystem but it will be
unmounted and re-mounted when the Cilium pod is restarted. This in turn will
cause BPF resources to be re-created which will cause network connectivity to
be disrupted.  Mounting the BPF filesystem in the host mount namespace will
ensure that the agent can be restarted without affecting connectivity of any
pods.

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

If you are using systemd to manage the kubelet, see the section
:ref:`bpffs_systemd`.

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


.. _ds_deploy:

Configuration
=============

.. tabs::
  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.8/cilium.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.9/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

Configuring etcd (Required)
---------------------------

After downloading the ``cilium.yaml`` file, open it with your text editor and
change the `ConfigMap` based on the following instructions.

First, make sure the ``etcd-config`` endpoints have the correct addresses of
your etcd nodes.

If you are running more than one node simply specify the complete of endpoints.
The list of endpoints can accept both domain names or IP addresses.
Make sure you specify the correct port used in your etcd node.

If etcd is running with `TLS <https://coreos.com/etcd/docs/latest/op-guide/security.html>`_,
there are a couple of changes that you need to do.

#. Make sure you have ``https`` in all endpoints;

#. Uncomment the line ``#ca-file: '/var/lib/etcd-secrets/etcd-ca'`` so that the
   certificate authority of the servers are known to Cilium;

#. Create a kubernetes secret with certificate authority file in kubernetes;

    #. Use certificate authority file, with the name ``ca.crt``, used to create in `etcd <https://coreos.com/etcd/docs/latest/op-guide/security.html#example-1-client-to-server-transport-security-with-https>`_;

    #. Create the secret by executing:

        .. code-block:: bash

            $ kubectl create secret generic -n kube-system cilium-etcd-secrets \
                --from-file=etcd-ca=ca.crt


If etcd is running with
`client to server authentication <https://coreos.com/etcd/docs/latest/op-guide/security.html#example-2-client-to-server-authentication-with-https-client-certificates>`_,
you need make more changes to the `ConfigMap`:

#. Uncomment both lines ``#key-file: '/var/lib/etcd-secrets/etcd-client-key'``
   and ``#cert-file: '/var/lib/etcd-secrets/etcd-client-crt'``;

#. Create a kubernetes secret with ``client.key`` and ``client.crt`` files in
   kubernetes.

    #. Use the file with the name ``client.key`` that contains the client key;

    #. Use the file with the name ``client.crt`` that contains the client
       certificate;

    #. Create the secret by executing:

        .. code-block:: bash

            $ kubectl create secret generic -n kube-system cilium-etcd-secrets \
                --from-file=etcd-ca=ca.crt \
                --from-file=etcd-client-key=client.key \
                --from-file=etcd-client-crt=client.crt


.. note::

    If you have set up the secret before you might see the error
    ``Error from server (AlreadyExists): secrets "cilium-etcd-secrets" already exists``
    you can simply delete it with
    ``kubectl delete secret -n kube-system cilium-etcd-secrets``
    and re-create it again.


.. note::

    When creating the kubernetes secrets just make sure you create it with
    all necessary files, ``ca.crt``, ``client.key`` and ``client.crt`` in a
    single ``kubectl create``.

Regarding the etcd configuration that is all you need to change in the
`ConfigMap`.

Adjusting Options (Optional)
----------------------------

In the `ConfigMap` there are a couple of options that can be changed
accordingly with your changes.

* ``debug`` - Sets to run Cilium in full debug mode, it can be changed at
  runtime;

* ``disable-ipv4`` - Disables IPv4 in Cilium and endpoints managed by Cilium;

* ``clean-cilium-state`` - Removes any Cilium state, e.g. BPF policy maps,
  before starting the Cilium agent;

* ``legacy-host-allows-world`` - If true, the policy with the entity
  ``reserved:host`` allows traffic from ``world``. If false, the policy needs
  to explicitly have the entity ``reserved:world`` to allow traffic from
  ``world``. It is recommended to set it to false. This option provides
  compatibility with Cilium 1.0 which was not able to differentiate between
  NodePort traffic and traffic from the host.

Any changes that you perform in the Cilium `ConfigMap` and in
``cilium-etcd-secrets`` ``Secret`` will require you to restart any existing
Cilium pods in order for them to pick the latest configuration.

The following `ConfigMap` is an example where the etcd cluster is running in 2
nodes, ``node-1`` and ``node-2`` with TLS, and client to server authentication
enabled.

.. code:: yaml

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: cilium-config
      namespace: kube-system
    data:
        endpoints:
        - https://node-1:31079
        - https://node-2:31079
        #
        # In case you want to use TLS in etcd, uncomment the 'ca-file' line
        # and create a kubernetes secret by following the tutorial in
        # https://cilium.link/etcd-config
        ca-file: '/var/lib/etcd-secrets/etcd-ca'
        #
        # In case you want client to server authentication, uncomment the following
        # lines and create a kubernetes secret by following the tutorial in
        # https://cilium.link/etcd-config
        key-file: '/var/lib/etcd-secrets/etcd-client-key'
        cert-file: '/var/lib/etcd-secrets/etcd-client-crt'

      # If you want to run cilium in debug mode change this value to true
      debug: "false"
      disable-ipv4: "false"
      # If you want to clean cilium state; change this value to true
      clean-cilium-state: "false"
      legacy-host-allows-world: "false"


Deploying
=========

After configuring the `ConfigMap` in ``cilium.yaml`` it is time to deploy it
using ``kubectl``:

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


Uninstalling
============

All cilium agents are managed as a `DaemonSet` which means that deleting the
`DaemonSet` will automatically stop and remove all pods which run Cilium on each
worker node:

.. code:: bash

        $ kubectl --namespace kube-system delete ds cilium

Advanced
========

CNI Details
-----------

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
          worker node, or the ``/etc/cni/net.d`` and ``/opt/cni/bin``
          directories must be mounted into the container where ``kubelet`` is
          running. This can be achieved with `Volumes` mounts.

The CNI auto installation is performed as follows:

1. The ``/etc/cni/net.d`` and ``/opt/cni/bin`` directories are mounted from the
   host filesystem into the pod where Cilium is running.

2. The file ``/etc/cni/net.d/05-cilium.conf`` is written in case it does not
   exist yet.

3. The binary ``cilium-cni`` is installed to ``/opt/cni/bin``. Any existing
   binary with the name ``cilium-cni`` is overwritten.

.. _install_cni:

Manually installing CNI
-----------------------

This step is typically already included in all Kubernetes distributions or
Kubernetes installers but can be performed manually:

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
      - name: "CNI_CONF_NAME"
        value: "05-cilium.conf"

The following variables are supported:

+---------------------+--------------------------------------+------------------------+
| Option              | Description                          | Default                |
+---------------------+--------------------------------------+------------------------+
| HOST_PREFIX         | Path prefix of all host mounts       | /host                  |
+---------------------+--------------------------------------+------------------------+
| CNI_DIR             | Path to mounted CNI directory        | ${HOST_PREFIX}/opt/cni |
+---------------------+--------------------------------------+------------------------+
| CNI_CONF_NAME       | Name of configuration file           | 05-cilium.conf         |
+---------------------+--------------------------------------+------------------------+

If you want to further adjust the CNI configuration you may do so by creating
the CNI configuration ``/etc/cni/net.d/05-cilium.conf`` manually:

.. code:: bash

    sudo mkdir -p /etc/cni/net.d
    sudo sh -c 'echo "{
        "name": "cilium",
        "type": "cilium-cni"
    }
    " > /etc/cni/net.d/05-cilium.conf'

Cilium will use any existing ``/etc/cni/net.d/05-cilium.conf`` file if it
already exists on a worker node and only creates it if it does not exist yet.

Enabling hostPort Support via CNI configuration
-----------------------------------------------

Some users may want to enable ``hostPort``. Currently, cilium does not natively 
support ``hostPort``. However, users can utilize ``hostPort`` via a CNI plugin
chain, by putting it in their ``cni-conf-dir`` (default ``/etc/cni/net.d``), e.g.:

.. code:: json

    {
        "cniVersion": "0.3.1",
        "name": "cilium-portmap",
        "plugins": [
                {
                        "type": "cilium-cni"
                },
                {
                        "type": "portmap",
                        "capabilities": { "portMappings": true }
                }
        ]
    }

For more information about ``hostPort``, check the `Kubernetes hostPort-CNI plugin documentation <https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-hostport>`_.

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

.. _bpffs_systemd:

Mounting BPFFS with systemd
---------------------------

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

