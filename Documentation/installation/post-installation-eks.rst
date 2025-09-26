**Post-installation steps:**

* After installing Cilium, create a `EKS Managed Nodegroup <https://eksctl.io/usage/eks-managed-nodes>`_. 
  

  * Below is an example on how to use `ClusterConfig <https://eksctl.io/usage/creating-and-managing-clusters/#using-config-files>`_
    file to create a node group:  
  
    .. code-block:: none

        cat <<EOF >node-group.yaml
        apiVersion: eksctl.io/v1alpha5
        kind: ClusterConfig

        metadata:
          name: cluster-1
          region: eu-west-1
          version: '1.30'
        
        managedNodeGroups:
          - name: ng-1
            desiredCapacity: 2
            privateNetworking: true
        EOF
        eksctl create nodegroup -f ./node-group.yaml
    
    Ensure cluster name and region matches the values in the ClusterConfig used to create the cluster. 