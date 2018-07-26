.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
      http://docs.cilium.io

.. _admin_install_options:

****************
Advanced Options
****************

This guide covers advanced installation options in a generic way that can be
applied on top of all other installation guides.

The following sections will describe runtime options that can be passed on to
the agent. Depending on your chosen form of installation, the steps required to
modify the agent options will be different:

 * Modify the DaemonSet file if you are using Kubernetes.
 * Modify the relevant unit or configuration file on all nodes or adjust your
   configuration management scripts if you are using systemd or another init
   system.


Running the agent on a node without a container runtime
=======================================================

If you want to run the Cilium agent on a node that will not host any
application containers, then that node may not have a container runtime
installed at all. You may still want to run the Cilium agent on the node to
ensure that local processes on that node can reach application containers on
other nodes. The default behavior of Cilium on startup when no container
runtime has been found is to abort startup. To avoid this abort, you can run
the ``cilium-agent`` with the following option.


.. code:: bash

    --container-runtime=none

