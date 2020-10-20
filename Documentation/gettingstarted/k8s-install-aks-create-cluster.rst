.. note:: **Do NOT specify the '--network-policy' flag** when creating the
    cluster, as this will cause the Azure CNI plugin to push down unwanted
    iptables rules.

.. code:: bash

   export RESOURCE_GROUP_NAME=aks-test
   export CLUSTER_NAME=aks-test
   export LOCATION=westeurope

   az group create --name $RESOURCE_GROUP_NAME --location $LOCATION
   az aks create \
       --resource-group $RESOURCE_GROUP_NAME \
       --name $CLUSTER_NAME \
       --location $LOCATION \
       --node-count 2 \
       --network-plugin azure

.. note:: When setting up AKS, it is important to use the flag
          ``--network-plugin azure`` to ensure that CNI mode is enabled.
