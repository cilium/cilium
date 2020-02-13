Scale up the cluster
====================

.. code:: bash

    eksctl get nodegroup --cluster eni-cluster
    CLUSTER			NODEGROUP	CREATED			MIN SIZE	MAX SIZE	DESIRED CAPACITY	INSTANCE TYPE	IMAGE ID
    test-cluster        	ng-25560078	2019-07-23T06:05:35Z	0		2		0			m5.large	ami-0923e4b35a30a5f53

.. code:: bash

    eksctl scale nodegroup --cluster eni-cluster -n ng-25560078 -N 2
    [ℹ]  scaling nodegroup stack "eksctl-test-cluster-nodegroup-ng-25560078" in cluster eksctl-test-cluster-cluster
    [ℹ]  scaling nodegroup, desired capacity from 0 to 2
