.. warning::
  Make sure you install `cilium-cli v0.15.0 <https://github.com/cilium/cilium-cli/releases/tag/v0.15.0>`_
  or later. The rest of instructions do not work with older versions of
  cilium-cli. To confirm the cilium-cli version that's installed in your system,
  run:

  .. code-block:: shell-session

    cilium version --client

  See :ref:`Cilium CLI upgrade notes <upgrade_cilium_cli_helm_mode>` for more details.

Install the latest version of the Cilium CLI. The Cilium CLI can be used to
install Cilium, inspect the state of a Cilium installation, and enable/disable
various features (e.g. clustermesh, Hubble).

.. tabs::
  .. group-tab:: Linux

    .. code-block:: shell-session

      CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
      CLI_ARCH=amd64
      if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
      curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
      sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
      sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
      rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}

  .. group-tab:: macOS

    .. code-block:: shell-session

      CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
      CLI_ARCH=amd64
      if [ "$(uname -m)" = "arm64" ]; then CLI_ARCH=arm64; fi
      curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-darwin-${CLI_ARCH}.tar.gz{,.sha256sum}
      shasum -a 256 -c cilium-darwin-${CLI_ARCH}.tar.gz.sha256sum
      sudo tar xzvfC cilium-darwin-${CLI_ARCH}.tar.gz /usr/local/bin
      rm cilium-darwin-${CLI_ARCH}.tar.gz{,.sha256sum}

  .. group-tab:: Other

    See the full page of `releases <https://github.com/cilium/cilium-cli/releases/latest>`_.

.. only:: not stable

   Clone the Cilium GitHub repository so that the Cilium CLI can access the
   latest unreleased Helm chart from the main branch:

   .. parsed-literal::

      git clone git@github.com:cilium/cilium.git
      cd cilium
