Deploy the connectivity test
----------------------------

Run the following command to validate that your cluster has proper network
connectivity:

.. code-block:: shell-session

   cilium connectivity test

The output should be similar to the following one:

::

   ℹ️  Monitor aggregation detected, will skip some flow validation steps
   ✨ [k8s-cluster] Creating namespace for connectivity check...
   (...)
   ---------------------------------------------------------------------------------------------------------------------
   📋 Test Report
   ---------------------------------------------------------------------------------------------------------------------
   ✅ 69/69 tests successful (0 warnings)

Congratulations! You have a fully functional Kubernetes cluster with Cilium. 🎉
