Run the following command to validate that your cluster has proper network
connectivity:

.. code-block:: shell-session

   $ cilium connectivity test
   ℹ️  Monitor aggregation detected, will skip some flow validation steps
   ✨ [k8s-cluster] Creating namespace for connectivity check...
   (...)
   ---------------------------------------------------------------------------------------------------------------------
   📋 Test Report
   ---------------------------------------------------------------------------------------------------------------------
   ✅ 69/69 tests successful (0 warnings)

.. note::

   The connectivity test may fail to deploy due to too many open files in one
   or more of the pods. If you notice this error, you can increase the
   ``inotify`` resource limits on your host machine (see
   `Pod errors due to "too many open files" <https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files>`_).

Congratulations! You have a fully functional Kubernetes cluster with Cilium. 🎉
