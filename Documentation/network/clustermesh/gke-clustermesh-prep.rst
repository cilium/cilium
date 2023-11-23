.. _gs_clustermesh_gke_prep:

**********************************
GKE-to-GKE Clustermesh Preparation
**********************************

This is a step-by-step guide on how to install and prepare 
Google Kubernetes Engine (GKE) clusters to meet the requirements 
for the clustermesh feature.

In this guide we will deploy two zonal, single node GKE clusters
in different regions for the express purpose of creating a
cost-effective environment to deploy a clustermesh to. Ideal for
development/learning purposes.

.. note::

        The steps below require the `gcloud <https://cloud.google.com/sdk/docs/install>`__ CLI tool

Create VPC
##########

1.  Create a VPC network in your GCP project. Environment variables are recommended as their
    values will be references in later steps.

    .. code-block:: bash

        #  feel free to choose your own VPC network name
        export PROJECT_ID="[GCP_PROJECT_ID]"
        export VPC_NETWORK="my-gke-network"

        gcloud compute networks create ${VPC_NETWORK} \
          --subnet-mode=auto \
          --project ${PROJECT_ID}

        gcloud compute firewall-rules create ${VPC_NETWORK}-allow-internal \
          --network ${VPC_NETWORK} \
          --allow tcp,udp,icmp \
          --source-ranges "10.128.0.0/9"


Deploy clusters
###############

1.  We will once again set some environment variables for values that will be reused in 
    later steps.

    .. code-block:: bash

        #  us-west1-a can be changed to any available location (`gcloud compute zones list`)
        export CLUSTER="gke-1"
        export ZONE="us-west1-a"
        export POD_CIDR="10.0.0.0/18"
        export SERVICES_CIDR="10.1.0.0/20"

    Below is an example to deploy one GKE cluster. To create more clusters, follow the
    steps again, using distinct cluster names, zones, pod CIDRs, and services CIDRs.

    .. note::

        During creation we also request to use ``"10.0.0.0/18"`` as the cluster (pod) CIDR
        and ``"10.1.0.0/20"`` as the services CIDR. You may select change the CIDRs provided
        they do not overlap with the pod and services CIDRs in your other cluster(s).

    .. code-block:: bash

        gcloud container clusters create ${CLUSTER} \
          --zone ${ZONE} \
          --node-locations ${ZONE} \
          --network=${VPC_NETWORK} \
          --enable-ip-alias \
          --cluster-ipv4-cidr=${POD_CIDR} \
          --services-ipv4-cidr=${SERVICES_CIDR} \
          --machine-type=e2-medium \
          --max-nodes=1 \
          --num-nodes=1 \
          --node-taints node.cilium.io/agent-not-ready=true:NoSchedule \
          --project ${PROJECT_ID}

        # Get kubectl credentials, the command will merge the new credentials
        # with the existing ~/.kube/config
        gcloud container clusters get-credentials ${CLUSTER} \
          --zone ${ZONE} \
          --project ${PROJECT_ID}
 
    The node taint is used to prevent pods from being deployed/started until Cilium
    has been installed.

2.  Install Cilium.

    .. important::

        Be sure to assign a unique ``cluster.id`` to each cluster.

    .. code-block:: bash

        cilium install \
            --version |CHART_VERSION| \
            --set cluster.id=1 \
            --set cluster.name=${CLUSTER}

3.  Check the status of Cilium.

    .. code-block:: bash

        cilium status   

4.  For each GKE cluster, save its context in an environment variable for use in
    the clustermesh setup process.

    GKE cluster context is a combination of project ID, location, and cluster name.

    .. code-block:: bash

        export CONTEXT1="gke_${PROJECT_ID}_${ZONE}_${CLUSTER}"


Peering VPC networks
########################

Google Cloud's VPCs are global in scope, so subnets within the same VPC can already communicate
with each other internally -- regardless of region. So there is no VPC peering required!

Node-to-node traffic between clusters is now possible. All requirements for 
clustermesh are met. Enabling clustermesh is explained in :ref:`gs_clustermesh`.

Please reference environment variables exported in step 4 for any commands that require
the Kubernetes context.
