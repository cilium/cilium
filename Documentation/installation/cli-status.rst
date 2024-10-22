To validate that Cilium has been properly installed, you can run

.. code-block:: shell-session

   $ cilium status --wait
      /¯¯\
   /¯¯\__/¯¯\    Cilium:         OK
   \__/¯¯\__/    Operator:       OK
   /¯¯\__/¯¯\    Hubble:         disabled
   \__/¯¯\__/    ClusterMesh:    disabled
      \__/

   DaemonSet         cilium             Desired: 2, Ready: 2/2, Available: 2/2
   Deployment        cilium-operator    Desired: 2, Ready: 2/2, Available: 2/2
   Containers:       cilium-operator    Running: 2
                     cilium             Running: 2
   Image versions    cilium             quay.io/cilium/cilium:v1.9.5: 2
                     cilium-operator    quay.io/cilium/operator-generic:v1.9.5: 2
