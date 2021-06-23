.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_helm:

***********************
Installation using Helm
***********************

This guide will show you how to install Cilium using `Helm
<https://helm.sh/>`_. This involves a couple of additional steps compared to
the :ref:`k8s_quick_install` and requires you to manually select the best
datapath and IPAM mode for your particular environment.

Install Cilium
==============

.. include:: k8s-install-download-release.rst

.. tabs::

    .. group-tab:: Generic

       These are the generic instructions on how to install Cilium into any
       Kubernetes cluster using the default configuration options below. Please
       see the other tabs for distribution/platform specific instructions which
       also list the ideal default configuration for particular platforms.

       **Default Configuration:**

       =============== =============== ==============
       Datapath        IPAM            Datastore
       =============== =============== ==============
       Encapsulation   Cluster Pool    Kubernetes CRD
       =============== =============== ==============

       .. include:: requirements-generic.rst

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system

    .. group-tab:: GCP/GKE

       .. include:: requirements-gke.rst

       **Install Cilium:**

       Extract the Cluster CIDR to enable native-routing:

       .. code-block:: shell-session

          NATIVE_CIDR="$(gcloud container clusters describe "${NAME}" --zone "${ZONE}" --format 'value(clusterIpv4Cidr)')"
          echo $NATIVE_CIDR

       Deploy Cilium release via Helm:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system \\
            --set nodeinit.enabled=true \\
            --set nodeinit.reconfigureKubelet=true \\
            --set nodeinit.removeCbrBridge=true \\
            --set cni.binPath=/home/kubernetes/bin \\
            --set gke.enabled=true \\
            --set ipam.mode=kubernetes \\
            --set nativeRoutingCIDR=$NATIVE_CIDR

       The NodeInit DaemonSet is required to prepare the GKE nodes as nodes are added
       to the cluster. The NodeInit DaemonSet will perform the following actions:

       * Reconfigure kubelet to run in CNI mode
       * Mount the eBPF filesystem

    .. group-tab:: Azure/AKS

       .. include:: requirements-aks.rst

       **Create a service principal:**

       In order to allow cilium-operator to interact with the Azure API, a
       service principal is required. You can reuse an existing service
       principal if you want but it is recommended to create a dedicated
       service principal for each Cilium installation:

       .. code-block:: shell-session

          az ad sp create-for-rbac --name cilium-operator-$RANDOM > azure-sp.json

       The contents of ``azure-sp.json`` should look like this:

       .. code-block:: json

          {
            "appId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "displayName": "cilium-operator",
            "name": "http://cilium-operator",
            "password": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "tenant": "cccccccc-cccc-cccc-cccc-cccccccccccc"
          }

       Extract the relevant credentials to access the Azure API:

       .. code-block:: shell-session

          AZURE_SUBSCRIPTION_ID="$(az account show | jq -r .id)"
          AZURE_CLIENT_ID="$(jq -r .appId < azure-sp.json)"
          AZURE_CLIENT_SECRET="$(jq -r .password < azure-sp.json)"
          AZURE_TENANT_ID="$(jq -r .tenant < azure-sp.json)"
          AZURE_NODE_RESOURCE_GROUP="$(az aks show --resource-group $RESOURCE_GROUP_NAME --name $CLUSTER_NAME | jq -r .nodeResourceGroup)"

       .. note::

          ``AZURE_NODE_RESOURCE_GROUP`` must be set to the resource group of
          the node pool, *not* the resource group of the AKS cluster.

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system \\
            --set azure.enabled=true \\
            --set azure.resourceGroup=$AZURE_NODE_RESOURCE_GROUP \\
            --set azure.subscriptionID=$AZURE_SUBSCRIPTION_ID \\
            --set azure.tenantID=$AZURE_TENANT_ID \\
            --set azure.clientID=$AZURE_CLIENT_ID \\
            --set azure.clientSecret=$AZURE_CLIENT_SECRET \\
            --set tunnel=disabled \\
            --set ipam.mode=azure \\
            --set enableIPv4Masquerade=false \\
            --set nodeinit.enabled=true

    .. group-tab:: AWS/EKS

       .. include:: requirements-eks.rst

       **Delete VPC CNI (``aws-node`` DaemonSet)**

       Cilium will manage ENIs instead of VPC CNI, so the ``aws-node``
       DaemonSet has to be deleted to prevent conflict behavior.

       .. code-block:: shell-session

          kubectl -n kube-system delete daemonset aws-node

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system \\
            --set eni.enabled=true \\
            --set ipam.mode=eni \\
            --set egressMasqueradeInterfaces=eth0 \\
            --set tunnel=disabled \\
            --set nodeinit.enabled=true

       .. note::

          This helm command sets ``eni.enabled=true`` and ``tunnel=disabled``,
          meaning that Cilium will allocate a fully-routable AWS ENI IP address
          for each pod, similar to the behavior of the `Amazon VPC CNI plugin
          <https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html>`_.

          This mode depends on a set of :ref:`ec2privileges` from the EC2 API.

          Cilium can alternatively run in EKS using an overlay mode that gives
          pods non-VPC-routable IPs.  This allows running more pods per
          Kubernetes worker node than the ENI limit, but means that pod
          connectivity to resources outside the cluster (e.g., VMs in the VPC
          or AWS managed services) is masqueraded (i.e., SNAT) by Cilium to use
          the VPC IP address of the Kubernetes worker node.  Excluding the
          lines for ``eni.enabled=true``, ``ipam.mode=eni`` and
          ``tunnel=disabled`` from the helm command will configure Cilium to
          use overlay routing mode (which is the helm default).

       Cilium is now deployed and you are ready to scale-up the cluster:

    .. group-tab:: OpenShift

       .. include:: requirements-openshift.rst

       **Install Cilium:**

       Cilium is a `Certified OpenShift CNI Plugin <https://access.redhat.com/articles/5436171>`_
       and is best installed when an OpenShift cluster is created using the OpenShift
       installer. Please refer to :ref:`k8s_install_openshift_okd` for more information.

    .. group-tab:: RKE

       .. include:: requirements-rke.rst

       **Install Cilium:**

       Install Cilium via ``helm install``:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
             --namespace $CILIUM_NAMESPACE

    .. group-tab:: k3s

       .. include:: requirements-k3s.rst

       **Install Cilium:**

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
             --namespace $CILIUM_NAMESPACE

.. include:: k8s-install-restart-pods.rst

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
