Preload the ``cilium`` image into each worker node in the kind cluster:

.. parsed-literal::

  docker pull cilium/cilium:|IMAGE_TAG|
  kind load docker-image cilium/cilium:|IMAGE_TAG|
