Install the latest version of the Cilium CLI on your local machine. The Cilium
CLI can be used to install Cilium, inspect the state of a Cilium installation,
and enable/disable a variety of functionality.

.. tabs::
  .. group-tab:: Linux

    .. code-block:: shell-session

      curl -LO https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz
      sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
      rm cilium-linux-amd64.tar.gz

  .. group-tab:: macOS

    .. code-block:: shell-session

      curl -LO https://github.com/cilium/cilium-cli/releases/latest/download/cilium-darwin-amd64.tar.gz
      sudo tar xzvfC cilium-darwin-amd64.tar.gz /usr/local/bin
      rm cilium-darwin-amd64.tar.gz

  .. group-tab:: Other

    See the full page of `releases <https://github.com/cilium/cilium-cli/releases/latest>`_.
