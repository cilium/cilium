Install the latest version of the Cilium CLI. The Cilium CLI can be used to
install Cilium, inspect the state of a Cilium installation, and enable/disable
various features (e.g. clustermesh, Hubble).

.. tabs::
  .. group-tab:: Linux

    .. code-block:: shell-session

      curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz{,.sha256sum}
      sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
      sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
      rm cilium-linux-amd64.tar.gz{,.sha256sum}

  .. group-tab:: macOS

    .. code-block:: shell-session

      curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/latest/download/cilium-darwin-amd64.tar.gz{,.sha256sum}
      shasum -a 256 -c cilium-darwin-amd64.tar.gz.sha256sum
      sudo tar xzvfC cilium-darwin-amd64.tar.gz /usr/local/bin
      rm cilium-darwin-amd64.tar.gz{,.sha256sum}

  .. group-tab:: Other

    See the full page of `releases <https://github.com/cilium/cilium-cli/releases/latest>`_.
