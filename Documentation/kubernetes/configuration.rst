.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _k8s_configuration:

*************
Configuration
*************

ConfigMap Options
-----------------

In the `ConfigMap` there are several options that can be configured according
to your preferences:

* ``debug`` - Sets to run Cilium in full debug mode, which enables verbose
  logging and configures BPF programs to emit more visibility events into the
  output of ``cilium monitor``.

* ``enable-ipv4`` - Enable IPv4 addressing support

* ``enable-ipv6`` - Enable IPv6 addressing support

* ``clean-cilium-bpf-state`` - Removes all BPF state from the filesystem on
  startup. Endpoints will be restored with the same IP addresses, but ongoing
  connections may be briefly disrupted and loadbalancing decisions will be
  lost, so active connections via the loadbalancer will break. All BPF state
  will be reconstructed from their original sources (for example, from
  kubernetes or the kvstore). This may be used to mitigate serious issues
  regarding BPF maps. This option should be turned off again after restarting
  the daemon.

* ``clean-cilium-state`` - Removes **all** Cilium state, including unrecoverable
  information such as all endpoint state, as well as recoverable state such as
  BPF state pinned to the filesystem, CNI configuration files, library code,
  links, routes, and other information. **This operation is irreversible**.
  Existing endpoints currently managed by Cilium may continue to operate as
  before, but Cilium will no longer manage them and they may stop working
  without warning. After using this operation, endpoints must be deleted and
  reconnected to allow the new instance of Cilium to manage them.

* ``monitor-aggregation`` - This option enables coalescing of tracing events in
  ``cilium monitor`` to only include periodic updates from active flows, or any
  packets that involve an L4 connection state change. Valid options are
  ``none``, ``low``, ``medium``, ``maximum``.

* ``preallocate-bpf-maps`` - Pre-allocation of map entries allows per-packet
  latency to be reduced, at the expense of up-front memory allocation for the
  entries in the maps. Set to ``true`` to optimize for latency. If this value
  is modified, then during the next Cilium startup connectivity may be
  temporarily disrupted for endpoints with active connections.

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
        ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'
        #
        # In case you want client to server authentication, uncomment the following
        # lines and create a kubernetes secret by following the tutorial in
        # https://cilium.link/etcd-config
        key-file: '/var/lib/etcd-secrets/etcd-client.key'
        cert-file: '/var/lib/etcd-secrets/etcd-client.crt'

      # If you want to run cilium in debug mode change this value to true
      debug: "false"
      enable-ipv4: "true"
      # If you want to clean cilium state; change this value to true
      clean-cilium-state: "false"

CNI
===

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

CRD Validation
==============

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
===========================

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

Container Runtimes
==================

CRIO
----

If you want to use CRIO, use the following YAML instead:

.. tabs::

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-crio.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-crio.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-crio.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-crio.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-crio.yaml


Since CRI-O does not automatically detect that a new CNI plugin has been
installed, you will need to restart the CRI-O daemon for it to pick up the
Cilium CNI configuration.

First make sure cilium is running:

::

    kubectl get pods -n kube-system -o wide
    NAME               READY     STATUS    RESTARTS   AGE       IP          NODE
    cilium-mqtdz       1/1       Running   0          3m       10.0.2.15   minikube

After that you can restart CRI-O:

::

    minikube ssh -- sudo systemctl restart crio

Finally, you need to restart the Cilium pod so it can re-mount
``/var/run/crio/crio.sock`` which was recreated by CRI-O

::

    kubectl delete -n kube-system pod -l k8s-app=cilium

Disable container runtime
-------------------------

If you want to run the Cilium agent on a node that will not host any
application containers, then that node may not have a container runtime
installed at all. You may still want to run the Cilium agent on the node to
ensure that local processes on that node can reach application containers on
other nodes. The default behavior of Cilium on startup when no container
runtime has been found is to abort startup. To avoid this abort, you can run
the ``cilium-agent`` with the following option.


.. code:: bash

    --container-runtime=none

