Install the latest version of the Cilium CLI. The Cilium CLI can be used to
install Cilium, inspect the state of a Cilium installation, and enable/disable
various features (e.g. clustermesh, Hubble).

.. tabs::
  .. group-tab:: Linux

    .. code-block:: shell-session

      CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/master/stable.txt)
      curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz{,.sha256sum}
      sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
      sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
      rm cilium-linux-amd64.tar.gz{,.sha256sum}

  .. group-tab:: macOS (Intel)

    .. code-block:: shell-session

      CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/master/stable.txt)
      curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-darwin-amd64.tar.gz{,.sha256sum}
      shasum -a 256 -c cilium-darwin-amd64.tar.gz.sha256sum
      sudo tar xzvfC cilium-darwin-amd64.tar.gz /usr/local/bin
      rm cilium-darwin-amd64.tar.gz{,.sha256sum}

  .. group-tab:: macOS (Apple Silicon - ARM)

    .. code-block:: shell-session

      CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/master/stable.txt)
      curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-darwin-arm64.tar.gz{,.sha256sum}
      shasum -a 256 -c cilium-darwin-arm64.tar.gz.sha256sum
      sudo tar xzvfC cilium-darwin-arm64.tar.gz /usr/local/bin
      rm cilium-darwin-arm64.tar.gz{,.sha256sum}

  .. group-tab:: Other

    See the full page of `releases <https://github.com/cilium/cilium-cli/releases/latest>`_.
