.. _gs_clustermesh_eks_prep:

**********************************
EKS-to-EKS Clustermesh Preparation
**********************************

This is a step-by-step guide on how to install and prepare AWS EKS (AWS Elastic Kubernetes Service) clusters to meet the requirements for the clustermesh feature.

In this guide you will install two EKS clusters and connect them together via clustermesh.

Install cluster one
###################

1.  Create environmental variables that will be appended to each resource name.

    .. code:: bash

        export NAME="$(whoami)-$RANDOM"
        export AWS_REGION="eu-west-2"

2.  Create a VPC

    .. note::
        Avoid using the ``172.17.0.0/16`` CIDR range for your VPC to prevent potential issues since certain `AWS services <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html>`__ utilize this range.
    
    .. code:: bash

        Cluster_1_VPC=$(aws ec2 create-vpc \
            --cidr-block 10.0.0.0/16 \
            --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=Cluster_1_VPC}]" \
            --region ${AWS_REGION} \
            --query 'Vpc.{VpcId:VpcId}' \
            --output text
        )

3.  Create Subnets.

    .. code:: bash

        # Create public subnets
        export Cluster_1_Public_Subnet_1=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_1_VPC} \
            --cidr-block 10.0.1.0/24 \
            --availability-zone ${AWS_REGION}a \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_1_Public_Subnet_1}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text 
        )

        export Cluster_1_Public_Subnet_2=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_1_VPC} \
            --cidr-block 10.0.2.0/24 \
            --availability-zone ${AWS_REGION}b \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_1_Public_Subnet_2}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text 
        )

        # Create private subnets
        export Cluster_1_Private_Subnet_1=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_1_VPC} \
            --cidr-block 10.0.3.0/24 \
            --availability-zone ${AWS_REGION}a \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_1_Private_Subnet_1}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text 
        )

        export Cluster_1_Private_Subnet_2=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_1_VPC} \
            --cidr-block 10.0.4.0/24 \
            --availability-zone ${AWS_REGION}b \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_1_Private_Subnet_2}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text
        )

4.  Create an internet gateway and NAT then attach it to the VPC.

    .. code:: bash

        # Create internet gateway
        export Cluster_1_IGW=$(aws ec2 create-internet-gateway \
            --tag-specifications "ResourceType=internet-gateway, Tags=[{Key=Name,Value=Cluster_1_IGW}]" \
            --query 'InternetGateway.InternetGatewayId' \
            --region ${AWS_REGION} \
            --output text
        )

        # Attach the internet gateway to the VPC
        aws ec2 attach-internet-gateway \
            --internet-gateway-id ${Cluster_1_IGW} \
            --vpc-id ${Cluster_1_VPC}

        # Create NAT gateway
        Cluster_1_EIP_1=$(aws ec2 allocate-address \
            --domain vpc \
             --tag-specifications "ResourceType=elastic-ip, Tags=[{Key=Name,Value=Cluster_1_EIP_1}]" \
            --query 'AllocationId' \
            --output text \
            --region ${AWS_REGION}
        )

        Cluster_1_EIP_2=$(aws ec2 allocate-address \
            --domain vpc \
             --tag-specifications "ResourceType=elastic-ip, Tags=[{Key=Name,Value=Cluster_1_EIP_2}]" \
            --query 'AllocationId' \
            --output text \
            --region ${AWS_REGION}
        )

        Cluster_1_NGW_1=$(aws ec2 create-nat-gateway \
            --subnet-id $Cluster_1_Public_Subnet_1 \
            --allocation-id ${Cluster_1_EIP_1} \
            --tag-specifications "ResourceType=natgateway, Tags=[{Key=Name,Value=Cluster_1_NGW_1}]" \
            --query 'NatGateway.{NatGatewayId:NatGatewayId}' \
            --output text
        )

        Cluster_1_NGW_2=$(aws ec2 create-nat-gateway \
            --subnet-id $Cluster_1_Public_Subnet_2 \
            --allocation-id ${EIP_ALLOCATION_ID_2} \
            --tag-specifications "ResourceType=natgateway, Tags=[{Key=Name,Value=Cluster_1_NGW_2}]" \
            --query 'NatGateway.{NatGatewayId:NatGatewayId}' \
            --output text
        )

5.  Create route tables, routes, and route table associations.

    .. code:: bash

        # Create a public route table
        export Cluster_1_Public_RT=$(aws ec2 create-route-table \
            --vpc-id ${Cluster_1_VPC} \
            --tag-specifications "ResourceType=route-table, Tags=[{Key=Name,Value=Cluster_1_Public_RT}]" \
            --query 'RouteTable.{RouteTableId:RouteTableId}' \
            --output text \
            --region ${AWS_REGION}
        )

        # Add a route to the internet gateway
        aws ec2 create-route \
            --route-table-id ${Cluster_1_Public_RT} \
            --destination-cidr-block 0.0.0.0/0 \
            --gateway-id ${Cluster_1_IGW}
        
        # Associate public subnets with the public route table
        aws ec2 associate-route-table \
            --subnet-id ${Cluster_1_Public_Subnet_1} \
            --route-table-id ${Cluster_1_Public_RT}

        aws ec2 associate-route-table \
            --subnet-id ${Cluster_1_Public_Subnet_2} \
            --route-table-id ${ROUTE_TABLE_ID_1}

        # Create private route tables
        export Cluster_1_Private_RT_1=$(aws ec2 create-route-table \
            --vpc-id ${Cluster_1_VPC} \
            --tag-specifications "ResourceType=route-table, Tags=[{Key=Name,Value=Cluster_1_Private_RT_1}]" \
            --query 'RouteTable.{RouteTableId:RouteTableId}' \
            --output text \
            --region ${AWS_REGION}
        )

        export Cluster_1_Private_RT_2=$(aws ec2 create-route-table \
            --vpc-id ${Cluster_1_VPC} \
            --tag-specifications "ResourceType=route-table, Tags=[{Key=Name,Value=Cluster_1_Private_RT_2}]" \
            --query 'RouteTable.{RouteTableId:RouteTableId}' \
            --output text \
            --region ${AWS_REGION}
        )

        # Add routes to the NAT gateway
        aws ec2 create-route \
            --route-table-id ${Cluster_1_Private_RT_1} \
            --destination-cidr-block 0.0.0.0/0 \
            --gateway-id ${Cluster_1_NGW_1}
        
        aws ec2 create-route \
            --route-table-id ${Cluster_1_Private_RT_2} \
            --destination-cidr-block 0.0.0.0/0 \
            --gateway-id ${Cluster_1_NGW_2}
        
        # Associate each private subnet with their respective private route table
        aws ec2 associate-route-table \
            --subnet-id ${Cluster_1_Private_Subnet_1} \
            --route-table-id ${Cluster_1_Private_RT_1}

        aws ec2 associate-route-table \
            --subnet-id ${Cluster_1_Private_Subnet_2} \
            --route-table-id ${Cluster_1_Private_RT_2}

6. Create a custom security group for the VPC. The default security group created with the EKS cluster only allows originating ingress traffic from the control-plane and other nodes within the cluster.

    .. code:: bash

        # Create a security group
        export Cluster_1_SG=$(aws ec2 create-security-group \
            --group-name Cluster_1_Security_Group \
            --description "Security group for Cluster 1" \
            --vpc-id ${Cluster_1_VPC} \
            --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=Cluster_1_SG}]" \
            --region ${AWS_REGION} \
            --output text \
            --query 'GroupId'
        )

        # Add an inbound rule for all ingress traffic from the control-plane and other worker nodes within the cluster. An inbound rule for all ingress traffic from Cluster 2 will be added in the next section.
        aws ec2 authorize-security-group-ingress \
            --group-id ${Cluster_1_SG} \
            --protocol all \
            --port 0 \
            --source-group ${Cluster_1_SG}\
            --region ${AWS_REGION}

7. You now have a virtual private cloud, subnets, nat gateway, internet gateway, and a route table. You can create an EKS cluster without a CNI and request to use our custom VNet and subnet.

    .. code:: bash

        cat <<EOF >eks-cluster-1.yaml
        apiVersion: eksctl.io/v1alpha5
        kind: ClusterConfig

        metadata:
          name: ${NAME}
          region: ${AWS_REGION}
        vpc:
          subnets:
            private:
              ${AWS_REGION}a: 
                id: ${Cluster_1_Private_Subnet_1}
              ${AWS_REGION}b:  
                id: ${Cluster_1_Private_Subnet_2}

        managedNodeGroups:
        - name: ng-1
            instanceType: t3.small
            securityGroups:
              attachIDs: ["${Cluster_1_SG}"]
            desiredCapacity: 2
            privateNetworking: true
            # Taint nodes so that application pods are
            # not scheduled/executed until Cilium is deployed.
            # Alternatively, see the note below.
            taints:
            - key: "node.cilium.io/agent-not-ready"
                value: "true"
                effect: "NoExecute"
        EOF

        eksctl create cluster -f ./eks-cluster-1.yaml

Install cluster two
###################

1.  Create environmental variables that will be appended to each resource name.

    .. code:: bash

        export NAME="$(whoami)-$RANDOM"
        export AWS_REGION="eu-west-2"

2.  Create a VPC

    .. note::
        Avoid using the ``172.17.0.0/16`` CIDR range for your VPC to prevent potential issues since certain `AWS services <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html>`__ utilize this range.
    
    .. code:: bash

        Cluster_2_VPC=$(aws ec2 create-vpc \
            --cidr-block 10.1.0.0/16 \
            --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=Cluster_2_VPC}]" \
            --region ${AWS_REGION} \
            --query 'Vpc.{VpcId:VpcId}' \
            --output text
        )

3.  Create Subnets.

    .. code:: bash

        # Create public subnets
        export Cluster_2_Public_Subnet_1=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_2_VPC} \
            --cidr-block 10.1.1.0/24 \
            --availability-zone ${AWS_REGION}a \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_2_Public_Subnet_1}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text 
        )

        export Cluster_2_Public_Subnet_2=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_2_VPC} \
            --cidr-block 10.1.2.0/24 \
            --availability-zone ${AWS_REGION}b \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_2_Public_Subnet_2}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text 
        )

        # Create private subnets
        export Cluster_2_Private_Subnet_1=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_2_VPC} \
            --cidr-block 10.1.3.0/24 \
            --availability-zone ${AWS_REGION}a \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_2_Private_Subnet_1}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text 
        )

        export Cluster_2_Private_Subnet_2=$(aws ec2 create-subnet \
            --vpc-id ${Cluster_2_VPC} \
            --cidr-block 10.1.4.0/24 \
            --availability-zone ${AWS_REGION}b \
            --tag-specifications "ResourceType=subnet, Tags=[{Key=Name,Value=Cluster_2_Private_Subnet_2}]" \
            --query 'Subnet.{SubnetId:SubnetId}' \
            --output text
        )

4.  Create an internet and NAT gateway, then attach it to the VPC.

    .. code:: bash

        # Create an internet gateway
        export Cluster_2_IGW=$(aws ec2 create-internet-gateway \
            --tag-specifications "ResourceType=internet-gateway, Tags=[{Key=Name,Value=Cluster_2_IGW}]" \
            --query 'InternetGateway.InternetGatewayId' \
            --region ${AWS_REGION} \
            --output text
        )

        # Attach the internet gateway to the VPC
        aws ec2 attach-internet-gateway \
            --internet-gateway-id ${Cluster_2_IGW} \
            --vpc-id ${Cluster_2_VPC}

        # Create elastic IP addresses
        Cluster_2_EIP_1=$(aws ec2 allocate-address \
            --domain vpc \
             --tag-specifications "ResourceType=elastic-ip, Tags=[{Key=Name,Value=Cluster_2_EIP_1}]" \
            --query 'AllocationId' \
            --output text \
            --region ${AWS_REGION}
        )

        Cluster_2_EIP_2=$(aws ec2 allocate-address \
            --domain vpc \
             --tag-specifications "ResourceType=elastic-ip, Tags=[{Key=Name,Value=Cluster_2_EIP_2}]" \
            --query 'AllocationId' \
            --output text \
            --region ${AWS_REGION}
        )

        # Create NAT gateways
        Cluster_2_NGW_1=$(aws ec2 create-nat-gateway \
            --subnet-id ${Cluster_2_Public_Subnet_1} \
            --allocation-id ${Cluster_2_EIP_1} \
            --tag-specifications "ResourceType=natgateway, Tags=[{Key=Name,Value=Cluster_2_NGW_1}]" \
            --query 'NatGateway.{NatGatewayId:NatGatewayId}' \
            --output text
        )

        Cluster_2_NGW_2=$(aws ec2 create-nat-gateway \
            --subnet-id ${Cluster_2_Public_Subnet_2} \
            --allocation-id ${Cluster_2_EIP_2} \
            --tag-specifications "ResourceType=natgateway, Tags=[{Key=Name,Value=Cluster_2_NGW_2}]" \
            --query 'NatGateway.{NatGatewayId:NatGatewayId}' \
            --output text
        )

5.  Create route tables, routes, and route table associations.

    .. code:: bash

        # Create a public route table
        export Cluster_2_Public_RT=$(aws ec2 create-route-table \
            --vpc-id ${Cluster_2_VPC} \
            --tag-specifications "ResourceType=route-table, Tags=[{Key=Name,Value=Cluster_2_Public_RT}]" \
            --query 'RouteTable.{RouteTableId:RouteTableId}' \
            --output text \
            --region ${AWS_REGION}
        )

        # Add a route to the internet gateway
        aws ec2 create-route \
            --route-table-id ${Cluster_2_Public_RT} \
            --destination-cidr-block 0.0.0.0/0 \
            --gateway-id ${Cluster_2_IGW}
        
        # Associate public subnets with the public route table
        aws ec2 associate-route-table \
            --subnet-id ${Cluster_2_Public_Subnet_1} \
            --route-table-id ${Cluster_2_Public_RT}

        aws ec2 associate-route-table \
            --subnet-id ${Cluster_2_Public_Subnet_2} \
            --route-table-id ${Cluster_2_Public_RT}

        # Create private route tables for each private subnet
        export Cluster_2_Private_RT_1=$(aws ec2 create-route-table \
            --vpc-id ${Cluster_2_VPC} \
            --tag-specifications "ResourceType=route-table, Tags=[{Key=Name,Value=Cluster_2_Private_RT_1}]" \
            --query 'RouteTable.{RouteTableId:RouteTableId}' \
            --output text \
            --region ${AWS_REGION}
        )

        export Cluster_2_Private_RT_2=$(aws ec2 create-route-table \
            --vpc-id ${Cluster_2_VPC} \
            --tag-specifications "ResourceType=route-table, Tags=[{Key=Name,Value=Cluster_2_Private_RT_2}]" \
            --query 'RouteTable.{RouteTableId:RouteTableId}' \
            --output text \
            --region ${AWS_REGION}
        )

        # Add routes to the NAT gateway
        aws ec2 create-route \
            --route-table-id ${Cluster_2_Private_RT_1} \
            --destination-cidr-block 0.0.0.0/0 \
            --gateway-id ${Cluster_2_NGW_1}
        
        aws ec2 create-route \
            --route-table-id ${Cluster_2_Private_RT_2} \
            --destination-cidr-block 0.0.0.0/0 \
            --gateway-id ${Cluster_2_NGW_2}
        
        # Associate each private subnet with their respective private route table
        aws ec2 associate-route-table \
            --subnet-id ${Cluster_2_Private_Subnet_1} \
            --route-table-id ${Cluster_2_Private_RT_1}

        aws ec2 associate-route-table \
            --subnet-id ${Cluster_2_Private_Subnet_2} \
            --route-table-id ${Cluster_2_Private_RT_2}

6. Create a custom security group for the VPC. The default security group created with the EKS cluster only allows originating ingress traffic from the control-plane and other nodes within the cluster.

    .. code:: bash

        # Create Security Group
        export Cluster_2_SG=$(aws ec2 create-security-group \
            --group-name Cluster_2_Security_Group \
            --description "Security group for Cluster 2" \
            --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=Cluster_2_SG}]" \
            --vpc-id ${Cluster_2_VPC} \
            --region ${AWS_REGION} \
            --output text \
            --query 'GroupId'
        )

        # Add an inbound rule for all ingress traffic from the control-plane and other worker nodes within the cluster.
        aws ec2 authorize-security-group-ingress \
            --group-id ${Cluster_2_SG} \
            --protocol all \
            --port 0 \
            --source-group ${Cluster_2_SG}\
            --region ${AWS_REGION}
        
        # Add an inbound rule for all ingress traffic from Cluster 1
        aws ec2 authorize-security-group-ingress \
            --group-id ${Cluster_2_SG} \
            --protocol all \
            --port 0 \
            --source-group ${Cluster_1_SG}\
            --region ${AWS_REGION}

        # In Cluster 1's security group, add an inbound rule for all ingress traffic from cluster 2.
        aws ec2 authorize-security-group-ingress \
            --group-id ${Cluster_1_SG} \
            --protocol all \
            --port 0 \
            --source-group ${Cluster_2_SG}\
            --region ${AWS_REGION}

7. You now have a virtual private cloud, subnets, NAT gateway, internet gateway, and a route table. You can create an EKS cluster without a CNI and request to use our custom VNet and subnet.

    .. code:: bash

        cat <<EOF >eks-cluster-2.yaml
        apiVersion: eksctl.io/v1alpha5
        kind: ClusterConfig

        metadata:
        name: ${NAME}
        region: ${AWS_REGION}
        vpc:
          subnets:
            private:
              ${AWS_REGION}a: 
                id: ${Cluster_2_Private_Subnet_1}
              ${AWS_REGION}b:  
                id: ${Cluster_2_Private_Subnet_2}

        managedNodeGroups:
          - name: ng-2
            instanceType: t3.small
            securityGroups:
              attachIDs: [${Cluster_2_SG}]
            desiredCapacity: 2
            privateNetworking: true
            taints:
              - key: "node.cilium.io/agent-not-ready"
                value: "true"
                effect: "NoExecute"
        EOF
        eksctl create cluster -f ./eks-cluster-2.yaml

Peering virtual networks
########################

1. Create VPC peering between the two VPCs.

    .. code:: bash

        # Create VPC peering connection
        export PEERING_CONNECTION_ID=$(aws ec2 create-vpc-peering-connection \
            --vpc-id ${Cluster_1_VPC} \
            --peer-vpc-id ${Cluster_2_VPC} \
            --peer-region ${AWS_REGION} \
            --output text \
            --query 'VpcPeeringConnection.VpcPeeringConnectionId'
        )

        # Grab the first VPC peering
        export PEERING_REQUEST_ID=$(aws ec2 describe-vpc-peering-connections \
            --filters "Name=requester-vpc-info.vpc-id,Values=${Cluster_1_VPC}" \
            --query "VpcPeeringConnections[0].VpcPeeringConnectionId" \
            --output text
        )

        # Accept VPC peering request
        aws ec2 accept-vpc-peering-connection \
            --vpc-peering-connection-id ${PEERING_REQUEST_ID} \
            --region ${AWS_REGION}

2. Forward traffic from Cluster 1 VPC to Cluster 2 VPC.

    .. code:: bash

        # Cluster 1
        # Add route to Private Route Table 1
        aws ec2 create-route \
            --route-table-id ${Cluster_1_Private_RT_1} \
            --destination-cidr-block 10.1.0.0/16 \
            --vpc-peering-connection-id ${PEERING_CONNECTION_ID} \
            --region ${AWS_REGION}

        # Add route to Private Route Table 2
        aws ec2 create-route \
            --route-table-id ${Cluster_1_Private_RT_2} \
            --destination-cidr-block 10.1.0.0/16 \
            --vpc-peering-connection-id ${PEERING_CONNECTION_ID} \
            --region ${AWS_REGION}

3. Forward traffic from Cluster 2 VPC to Cluster 1 VPC.

    .. code:: bash

        # Cluster 2
        # Add route to Private Route Table 1
        aws ec2 create-route \
            --route-table-id ${Cluster_2_Private_RT_1} \
            --destination-cidr-block 10.0.0.0/16 \
            --vpc-peering-connection-id ${PEERING_CONNECTION_ID} \
            --region ${AWS_REGION}

        # Add route to Private Route Table 2
        aws ec2 create-route \
            --route-table-id ${Cluster_2_Private_RT_2} \
            --destination-cidr-block 10.0.0.0/16 \
            --vpc-peering-connection-id ${PEERING_CONNECTION_ID} \
            --region ${AWS_REGION}

Nodes in different clusters can now communicate directly. All clustermesh requirements are fulfilled. 
Instructions for enabling clustermesh are detailed in the :ref:`gs_clustermesh` section.
