.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. note::

   First, make sure you have Helm 3 `installed <https://helm.sh/docs/intro/install/>`_.

   If you have (or planning to have) Helm 2 charts (and Tiller) in the same cluster,
   there should be no issue as both version are mutually compatible in  order to support
   `gradual migration <https://helm.sh/docs/topics/v2_v3_migration/>`_. Cilium chart is
   targeting Helm 3 (v3.0.3 and above).

.. only:: stable

   Setup Helm repository:

    .. code:: bash

        helm repo add cilium https://helm.cilium.io/

.. only:: not stable

   Download the Cilium release tarball and change to the kubernetes install directory:

    .. parsed-literal::

        curl -LO |SCM_ARCHIVE_LINK|
        tar xzvf |SCM_ARCHIVE_FILENAME|
        cd |SCM_ARCHIVE_NAME|/install/kubernetes
