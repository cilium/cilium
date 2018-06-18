.. _coreos_gs_guide:

*************************
CoreOS Installation Guide
*************************

This document serves as a guide to get Cilium up-and-running on CoreOS.

If you haven't read the :ref:`intro` yet, we encourage you to do that first.

For an introduction about how to setup Kubernetes with CoreOS, we recommend
following along with the `Core OS guide
<https://coreos.com/kubernetes/docs/latest/getting-started.html>`_.  The CoreOS
guide serves as a reference to setting up Kubernetes components (e.g.,
kube-apiserver, kube-scheduler, certificates, etc.), while this page focuses
specifically on the modifications needed to get Cilium functioning with CoreOS.

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_. With Cilium contributors across
the globe, there is almost always someone available to help.


Minimum Requirements
====================

* Make sure you understand the various `CoreOS deployment options`_.
* *etcd*
   * ``etcd`` must be at version ``>= 3.1.0``. To set up etcd, follow the
     `CoreOS etcd deployment instructions`_ for setting up an etcd cluster.
* *kubectl*
   * It is also required that you install ``kubectl`` version ``>= 1.7.0`` as
     described in the `Kubernetes Docs`_.

.. _`CoreOS deployment options`: https://coreos.com/kubernetes/docs/latest/getting-started.html#deployment-options
.. _`CoreOS etcd deployment instructions`: https://coreos.com/kubernetes/docs/latest/getting-started.html#deploy-etcd-cluster
.. _`Kubernetes Docs`: https://kubernetes.io/docs/tasks/tools/install-kubectl/

Setup Master Nodes
==================

Step 1: Create TLS Assets
-------------------------

Follow the `CoreOS instructions for creating TLS assets on master nodes
<https://coreos.com/kubernetes/docs/latest/getting-started.html#generate-kubernetes-tls-assets>`_
and `install the TLS assets needed for the master nodes
<https://coreos.com/kubernetes/docs/latest/deploy-master.html#tls-assets>`_ for
secure communication with the kube-apiserver.


Step 2: Setup Kubelet
---------------------

On CoreOS, Kubelet (the Kubernetes agent that runs on each node, more info
`here <https://kubernetes.io/docs/admin/kubelet/>`_) runs as a container. In
order to securely communicate with the API server, kubelet uses the TLS assets
we generated as part of Step 1.

Master nodes are usually not scheduled to run workloads, so we provide the
``-register-schedulable=false`` in the example YAML excerpt below. This ensures
that workloads are only scheduled on worker nodes.

Since we are setting up Kubelet to use Cilium, we want to configure its
networking to utilize CNI (Container Networking Interface). This ensures that
each pod that is created can communicate with one another within the cluster
with Cilium networking configured.

* Replace ${ADVERTISE_IP} with this node's publicly routable IP.
* Replace ${DNS_SERVICE_IP}. For more information about what this IP is, refer
  to `the CoreOS documentation for Kubernetes deployment options
  <https://coreos.com/kubernetes/docs/latest/getting-started.html#deployment-options>`_. 
* Replace ${KUBE_VERSION} with a version  ``>= 1.7.0``.
* Cilium-specific configuration    

    * Mount the CNI configuration directory you created in step 1 so Kubelet
      can pick up the CNI configuration from the host filesystem:

         ::

             --volume etc-cni,kind=host,source=/etc/cni/net.d \
             --mount volume=etc-cni,target=/etc/cni/net.d

    * Mount the directory where CNI plugins are installed:

        ::

             --volume cni-bin,kind=host,source=/opt/cni/bin \
             --mount volume=cni-bin,target=/opt/cni/bin

    * `Mount the BPF filesystem
      <http://cilium.readthedocs.io/en/latest/kubernetes/install/?#mounting-the-bpf-fs-optional>`_ so that
      the information stored there persists across Cilium restarts:

        ::
             
             ExecStartPre=/bin/bash -c ' \\
               if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
                 /bin/mount bpffs /sys/fs/bpf -t bpf; \\
               fi'

    * Also ensure that you specify that the network plugin is CNI: 

        ::  

             --network-plugin=cni

    * Specify the CNI directory to correspond to the mount you provided earlier
      where the CNI configuration is located:
    
        ::

             --cni-conf-dir=/etc/cni/net.d

``/etc/systemd/system/kubelet.service``

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

Follow the `CoreOS instructions for setting up the API server
<https://coreos.com/kubernetes/docs/latest/deploy-master.html#set-up-the-kube-apiserver-pod>`_. 

Make sure that you set the version of the kube-apiserver to whatever version
you are using for the Kubelet as well, e.g.:

::

    quay.io/coreos/hyperkube:v${KUBE_VERSION}_coreos.0

Step 4: Setup kube-controller-manager on the master nodes
---------------------------------------------------------

Per the `CoreOS guide
<https://coreos.com/kubernetes/docs/latest/deploy-master.html#set-up-the-kube-controller-manager-pod>`_,
"the controller manager is responsible for reconciling any required actions
based on changes to `Replication Controllers
<https://coreos.com/kubernetes/docs/latest/replication-controller.html>`_. For
example, if you increased the replica count, the controller manager would
generate a scale up event, which would cause a new Pod to get scheduled in the
cluster. The controller manager communicates with the API to submit these
events.

Create ``/etc/kubernetes/manifests/kube-controller-manager.yaml``. It will use
the TLS certificate placed on disk earlier."

* Add ``--allocate-node-cidrs`` to ensure that the kube-controller-manager
  allocates unique pod CIDR blocks for each node in the cluster.
* Substitute ${CLUSTER_CIDR} with the CIDR range for pods in your cluster.
* Substitute ${SERVICE_CLUSTER_IP_RANGE} with the IP range used for service IPs
  in your cluster.
* Set NODE_CIDR_MASK_SIZE to a size that you want for each CIDR block on each
  node.

``/etc/kubernetes/manifests/kube-controller-manager.yaml.``

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

Cilium has no special requirements for setting up the kube-scheduler on master
nodes. Follow the `CoreOS instructions for setting up kube-scheduler
<https://coreos.com/kubernetes/docs/latest/deploy-master.html#set-up-the-kube-scheduler-pod>`_.

Make sure that you set the version of the kube-apiserver to whatever version
you are using for the Kubelet as well, e.g.:

::

    quay.io/coreos/hyperkube:v${KUBE_VERSION}_coreos.0

Step 6: Setup kube-proxy on master nodes
----------------------------------------

The next step is to setup kube-proxy as a static pod on all master nodes.
Create the file ``/etc/kubernetes/manifests/kube-proxy.yaml`` and substitute
the following variables:

* ``${CLUSTER_CIDR}`` with the CIDR range for pods in your cluster.
* ``${KUBE_VERSION}`` with a version  ``>= 1.7.0``.

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

Follow `the CoreOS instructions to health check Kubernetes services
<https://coreos.com/kubernetes/docs/latest/deploy-master.html#basic-health-checks>`_.


Step 9: Setup Kubectl to Communicate With Your Cluster
------------------------------------------------------

Follow `the CoreOS instructions to download kubectl
<https://coreos.com/kubernetes/docs/latest/configure-kubectl.html#download-the-kubectl-executable>`_.

* Replace ${MASTER_HOST} with the master node address or name used in previous steps
* Replace ${CA_CERT} with the absolute path to the ca.pem created in previous steps
* Replace ${ADMIN_KEY} with the absolute path to the admin-key.pem created in previous steps
* Replace ${ADMIN_CERT} with the absolute path to the admin.pem created in previous steps

:: 

    kubectl config set-cluster default-cluster --server=https://${MASTER_IP} --certificate-authority=${CA_CERT} --embed-certs=true 
    kubectl config set-credentials default-admin --certificate-authority=${CA_CERT} --client-key=${ADMIN_KEY} --client-certificate=${ADMIN_CERT} --embed-certs=true
    kubectl config set-context default-system --cluster=default-cluster --user=default-admin 
    kubectl config use-context default-system 

This will populate the Kubeconfig file with the contents of the certificates,
which is needed for Cilium to authenticate against the Kubernetes API when it
is launched in the next step.

Alternatively, you can run the above commands without ``--embed-certs=true``,
and then mount the paths to the certificates and keys from the host filesystem
in ``cilium.yaml``.

Follow `the CoreOS instructions to validate that kubectl has been configured
correctly
<https://coreos.com/kubernetes/docs/latest/configure-kubectl.html#verify-kubectl-configuration-and-connection>`_.


.. _cilium-daemonset-deployment:

Step 10: Deploy Cilium DaemonSet
--------------------------------

* Follow the instructions for :ref:`ds_deploy`. We recommend using the etcd
  cluster you have set up as the key-value store for Cilium.

Setup Worker Nodes
==================

Step 1: Create TLS Assets
-------------------------

Cilium has no special requirements for setting up the TLS assets on worker
nodes. Follow the `CoreOS instructions for creating TLS assets on worker nodes
<https://coreos.com/kubernetes/docs/latest/deploy-workers.html#tls-assets>`_
for secure communication with the ``kube-apiserver``.

Step 2: Setup Kubelet
---------------------

On CoreOS, Kubelet (the Kubernetes agent that runs on each node, more info
`here <https://kubernetes.io/docs/admin/kubelet/>`_) runs as a container. In
order to securely communicate with the API server, kubelet uses the TLS assets
we generated as part of Step 1.

Since we are setting up Kubelet to use Cilium, we want to configure its
networking to utilize CNI (Container Networking Interface). This ensures that
each pod that is created can communicate with one another within the cluster
with Cilium networking configured.

* Replace ${MASTER_HOST}
* Replace ${ADVERTISE_IP} with this node's publicly routable IP.
* Replace ${DNS_SERVICE_IP}. For more information about what this IP is, refer to `the CoreOS documentation for Kubernetes deployment options <https://coreos.com/kubernetes/docs/latest/getting-started.html#deployment-options>`_. 
* Replace ${KUBE_VERSION} with a version  ``>= 1.7.0``.
* Cilium-specific configuration

    * Mount the CNI configuration directory you created in step 1 so Kubelet can pick up the CNI configuration from the host filesystem:

        ::

            --volume etc-cni,kind=host,source=/etc/cni/net.d \
            --mount volume=etc-cni,target=/etc/cni/net.d

    * Mount the directory where CNI plugins are installed:

        ::

            --volume cni-bin,kind=host,source=/opt/cni/bin \
            --mount volume=cni-bin,target=/opt/cni/bin 

    * `Mount the BPF filesystem <http://cilium.readthedocs.io/en/latest/kubernetes/install/?#mounting-the-bpf-fs-optional>`_ so that the information stored there persists across Cilium restarts:

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

``/etc/systemd/system/kubelet.service``
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

* ``${KUBE_VERSION}`` with a version  ``>= 1.7.0``.
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

Cilium has no special requirements for setting up the ``kubeconfig`` for
``kubelet`` on worker nodes. Please follow `the CoreOS instructions to setup
the worker-kubeconfig
<https://coreos.com/kubernetes/docs/latest/deploy-workers.html#set-up-kubeconfig>`_.

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

When we deployed Cilium as part of :ref:`cilium-daemonset-deployment`, the
Daemon Set expects the Kubeconfig to be located at the same location on each
node in the cluster. So, you need to make sure that the location and contents
of the kubeconfig for the worker node is the same as that which Cilium is using
on the master nodes, e.g., ``~/.kube/config``.

Step 7: Setup kubectl and deploy add-ons
----------------------------------------

Follow `the CoreOS instructions for setting up kube-dns and kube-dashboard <https://coreos.com/kubernetes/docs/latest/deploy-addons.html>`_.
