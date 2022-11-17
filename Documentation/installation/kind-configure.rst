Configuring kind cluster creation is done using a YAML configuration file.
This step is necessary in order to disable the default CNI and replace it with
Cilium.

Create a :download:`kind-config.yaml <./kind-config.yaml>` file based on the
following template. It will create a cluster with 3 worker nodes and 1
control-plane node.

.. literalinclude:: kind-config.yaml
   :language: yaml

By default, the latest version of Kubernetes from when the kind release was
created is used.

To change the version of Kubernetes being run,  ``image`` has to be defined for
each node. See the
`Node Configuration <https://kind.sigs.k8s.io/docs/user/configuration/#nodes>`_
documentation for more information.

.. tip::
    By default, kind uses the following pod and service subnets::

        Networking.PodSubnet     = "10.244.0.0/16"
        Networking.ServiceSubnet = "10.96.0.0/12"

    If any of these subnets conflicts with your local network address range,
    update the ``networking`` section of the kind configuration file to specify
    different subnets that do not conflict or you risk having connectivity
    issues when deploying Cilium. For example:

    .. code-block:: yaml

         networking:
           disableDefaultCNI: true
           podSubnet: "10.10.0.0/16"
           serviceSubnet: "10.11.0.0/16"
