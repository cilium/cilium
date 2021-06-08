.. tabs::

   .. group-tab:: Linux

      Download the latest hubble release:

      .. code-block:: shell-session

         export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
         curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz{,.sha256sum}
         sha256sum --check hubble-linux-amd64.tar.gz.sha256sum
         sudo tar xzvfC hubble-linux-amd64.tar.gz /usr/local/bin
         rm hubble-linux-amd64.tar.gz{,.sha256sum}

   .. group-tab:: MacOS

      Download the latest hubble release:

      .. code-block:: shell-session

         export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
         curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-darwin-amd64.tar.gz{,.sha256sum}
         shasum -a 256 -c hubble-darwin-amd64.tar.gz.sha256sum
         sudo tar xzvfC hubble-darwin-amd64.tar.gz /usr/local/bin
         rm hubble-darwin-amd64.tar.gz{,.sha256sum}

   .. group-tab:: Windows

      Download the latest hubble release:

      .. code-block:: shell-session

         curl -LO "https://raw.githubusercontent.com/cilium/hubble/master/stable.txt"
         set /p HUBBLE_VERSION=<stable.txt
         curl -LO "https://github.com/cilium/hubble/releases/download/%HUBBLE_VERSION%/hubble-windows-amd64.tar.gz"
         curl -LO "https://github.com/cilium/hubble/releases/download/%HUBBLE_VERSION%/hubble-windows-amd64.tar.gz.sha256sum"
         certutil -hashfile hubble-windows-amd64.tar.gz SHA256
         type hubble-windows-amd64.tar.gz.sha256sum
         :: verify that the checksum from the two commands above match
         tar zxf hubble-windows-amd64.tar.gz

      and move the ``hubble.exe`` CLI to a directory listed in the ``%PATH%`` environment variable after
      extracting it from the tarball.
