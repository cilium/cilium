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

    .. group-tab:: GKE

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
            --set ipv4NativeRoutingCIDR=$NATIVE_CIDR

       The NodeInit DaemonSet is required to prepare the GKE nodes as nodes are added
       to the cluster. The NodeInit DaemonSet will perform the following actions:

       * Reconfigure kubelet to run in CNI mode
       * Mount the eBPF filesystem

    .. group-tab:: AKS

       .. include:: ../installation/requirements-aks.rst

       .. tabs::

          .. tab:: BYOCNI

             .. include:: ../installation/requirements-aks-byocni.rst

             **Install Cilium:**

             Deploy Cilium release via Helm:

             .. parsed-literal::

                helm install cilium |CHART_RELEASE| \\
                  --namespace kube-system \\
                  --set aksbyocni.enabled=true \\
                  --set nodeinit.enabled=true

          .. tab:: Legacy Azure IPAM

             .. include:: ../installation/requirements-aks-azure-ipam.rst

             **Create a Service Principal:**

             In order to allow cilium-operator to interact with the Azure API, a
             Service Principal with ``Contributor`` privileges over the AKS cluster is
             required (see :ref:`Azure IPAM required privileges <ipam_azure_required_privileges>`
             for more details). It is recommended to create a dedicated Service
             Principal for each Cilium installation with minimal privileges over the
             AKS node resource group:

             .. code-block:: shell-session

                AZURE_SUBSCRIPTION_ID=$(az account show --query "id" --output tsv)
                AZURE_NODE_RESOURCE_GROUP=$(az aks show --resource-group ${RESOURCE_GROUP} --name ${CLUSTER_NAME} --query "nodeResourceGroup" --output tsv)
                AZURE_SERVICE_PRINCIPAL=$(az ad sp create-for-rbac --scopes /subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_NODE_RESOURCE_GROUP} --role Contributor --output json --only-show-errors)
                AZURE_TENANT_ID=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.tenant')
                AZURE_CLIENT_ID=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.appId')
                AZURE_CLIENT_SECRET=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.password')

             .. note::

                The ``AZURE_NODE_RESOURCE_GROUP`` node resource group is *not* the
                resource group of the AKS cluster. A single resource group may hold
                multiple AKS clusters, but each AKS cluster regroups all resources in
                an automatically managed secondary resource group. See `Why are two
                resource groups created with AKS? <https://docs.microsoft.com/en-us/azure/aks/faq#why-are-two-resource-groups-created-with-aks>`__
                for more details.

                This ensures the Service Principal only has privileges over the AKS
                cluster itself and not any other resources within the resource group.

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
                  --set routingMode=native \\
                  --set ipam.mode=azure \\
                  --set enableIPv4Masquerade=false \\
                  --set nodeinit.enabled=true

    .. group-tab:: EKS

       .. include:: requirements-eks.rst

       **Patch VPC CNI (aws-node DaemonSet)**

       Cilium will manage ENIs instead of VPC CNI, so the ``aws-node``
       DaemonSet has to be patched to prevent conflict behavior.

       .. code-block:: shell-session

          kubectl -n kube-system patch daemonset aws-node --type='strategic' -p='{"spec":{"template":{"spec":{"nodeSelector":{"io.cilium/aws-node-enabled":"true"}}}}}'

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system \\
            --set eni.enabled=true \\
            --set ipam.mode=eni \\
            --set egressMasqueradeInterfaces=eth0 \\
            --set routingMode=native

       .. note::

          This helm command sets ``eni.enabled=true`` and ``routingMode=native``,
          meaning that Cilium will allocate a fully-routable AWS ENI IP address
          for each pod, similar to the behavior of the `Amazon VPC CNI plugin
          <https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html>`_.

          This mode depends on a set of :ref:`ec2privileges` from the EC2 API.

          Cilium can alternatively run in EKS using an overlay mode that gives
          pods non-VPC-routable IPs.  This allows running more pods per
          Kubernetes worker node than the ENI limit, but means that pod
          connectivity to resources outside the cluster (e.g., VMs in the VPC
          or AWS managed services) is masqueraded (i.e., SNAT) by Cilium to use
          the VPC IP address of the Kubernetes worker node. To set up Cilium 
          overlay mode, follow the steps below:

            1. Excluding the lines for ``eni.enabled=true``, ``ipam.mode=eni`` and 
               ``routingMode=native`` from the helm command will configure Cilium to use
               overlay routing mode (which is the helm default).
            2. Flush iptables rules added by VPC CNI

               .. code-block:: shell-session
               
                  iptables -t nat -F AWS-SNAT-CHAIN-0 \\
                     && iptables -t nat -F AWS-SNAT-CHAIN-1 \\
                     && iptables -t nat -F AWS-CONNMARK-CHAIN-0 \\
                     && iptables -t nat -F AWS-CONNMARK-CHAIN-1

         Some Linux distributions use a different interface naming convention.
         If you use masquerading with the option ``egressMasqueradeInterfaces=eth0``,
         remember to replace ``eth0`` with the proper interface name.

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
             --namespace $CILIUM_NAMESPACE \\
             --set operator.replicas=1

    .. group-tab:: Rancher Desktop

       **Configure Rancher Desktop:**

       To install Cilium on `Rancher Desktop <https://rancherdesktop.io>`_,
       perform the following steps:

       .. include:: rancher-desktop-configure.rst

       **Install Cilium:**

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
             --namespace $CILIUM_NAMESPACE \\
             --set operator.replicas=1 \\
             --set cni.binPath=/usr/libexec/cni

    .. group-tab:: Alibaba ACK

        .. include:: ../installation/alibabacloud-eni.rst

.. include:: k8s-install-restart-pods.rst

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
