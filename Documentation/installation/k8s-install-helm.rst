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

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. parsed-literal::

          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system \\
            --set aksbyocni.enabled=true

       .. note::

          Installing Cilium via helm is supported only for AKS BYOCNI cluster and
          not for Azure CNI Powered by Cilium clusters.

    .. group-tab:: EKS

       **Retrieve cluster API URL and Port:**

       Since the cluster is set up with the kube-proxy explicitly disabled, no component is handling the cluster's 
       internal L4 load balancing. Therefore, the cilium agent needs to be made aware of the EKS cluster's API URL and port. 
       These details can be retrieved using ``kubectl``. Run the command below to retrieve these details. 
       
       .. code-block:: bash

          kubectl cluster-info
       
       The cluster API URL can also be retrieved using the AWS CLI. Run the command below to do this. 

       .. code-block:: bash 

          aws eks describe-cluster --name <your-cluster-name> --region <your-cluster-region> | jq -r .cluster.endpoint

       .. code-block:: bash 

         API_SERVER_IP=<your_api_server_FQDN>\
         API_SERVER_PORT=443

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. parsed-literal::
          
          helm install cilium |CHART_RELEASE| \\
            --namespace kube-system \\
            --set eni.enabled=true \\
            --set k8sServiceHost={API_SERVER_IP} \\
            --set k8sServicePort={API_SERVER_PORT}

       .. note::
          Make sure to remove **https://** from your API server FQDN before running the Cilium installation commands
          or this will cause the Cilium operator and agent pods to crash. 


          This helm command sets ``eni.enabled=true``,
          meaning that Cilium will allocate a fully-routable AWS ENI IP address
          for each pod, similar to the behavior of the `Amazon VPC CNI plugin
          <https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html>`_.

          This mode depends on a set of :ref:`ec2privileges` from the EC2 API.

          Cilium can alternatively run in EKS using an overlay mode that gives
          pods non-VPC-routable IPs.  This allows running more pods per
          Kubernetes worker node than the ENI limit but includes the following caveats:

            1. Pod connectivity to resources outside the cluster (e.g., VMs in the VPC
               or AWS managed services) is masqueraded (i.e., SNAT) by Cilium to use the
               VPC IP address of the Kubernetes worker node.
            2. The EKS API Server is unable to route packets to the overlay network. This
               implies that any `webhook <https://kubernetes.io/docs/reference/access-authn-authz/webhook/>`_
               which needs to be accessed must be host networked or exposed through a service
               or ingress.

          To set up Cilium overlay mode, follow the steps below:

            1. Excluding the line ``eni.enabled=true`` from the helm command will configure Cilium to use
               overlay routing mode (which is the helm default).

       .. include:: requirements-eks.rst

    .. group-tab:: OpenShift

       .. include:: requirements-openshift.rst

       **Install Cilium:**

       Cilium is a `Certified OpenShift CNI Plugin <https://access.redhat.com/articles/5436171>`_
       and is best installed when an OpenShift cluster is created using the OpenShift
       installer. Please refer to :ref:`k8s_install_openshift_okd` for more information.

    .. group-tab:: RKE

       .. include:: requirements-rke.rst

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

    .. group-tab:: Talos Linux

       To install Cilium on `Talos Linux <https://www.talos.dev/>`_,
       perform the following steps.

       .. include:: k8s-install-talos-linux.rst

    .. group-tab:: Alibaba ACK

        .. include:: ../installation/alibabacloud-eni.rst

.. admonition:: Video
  :class: attention

  If you'd like to learn more about Cilium Helm values, check out `eCHO episode 117: A Tour of the Cilium Helm Values <https://www.youtube.com/watch?v=ni0Uw4WLHYo>`__.

.. include:: k8s-install-restart-pods.rst

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
