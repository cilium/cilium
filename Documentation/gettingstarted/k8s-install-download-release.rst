`Install Helm`_ version 3.0.0 or higher to prepare generating the deployment
artifacts based on the Helm templates.

.. _Install Helm: https://helm.sh/docs/using_helm/#install-helm

.. only:: stable

   Setup helm repository:

    .. code:: bash

        helm repo add cilium https://helm.cilium.io/

.. only:: not stable

   Download the Cilium release tarball and change to the kubernetes install directory:

    .. parsed-literal::

        curl -LO |SCM_ARCHIVE_LINK|
        tar xzvf |SCM_ARCHIVE_FILENAME|
        cd |SCM_ARCHIVE_NAME|/install/kubernetes
