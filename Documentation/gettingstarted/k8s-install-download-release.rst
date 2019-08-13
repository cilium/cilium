Download the Cilium release tarball and change to the kubernetes install directory:

.. parsed-literal::

    curl -LO |SCM_ARCHIVE_LINK|
    tar xzvf |SCM_ARCHIVE_FILENAME|
    cd |SCM_ARCHIVE_NAME|/install/kubernetes

`Install Helm`_ to prepare generating the deployment artifacts based on the
Helm templates.

.. _Install Helm: https://helm.sh/docs/using_helm/#install-helm
