.. tabs::

   .. group-tab:: Linux

      Download the latest hubble release:

      .. parsed-literal::

         export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
         curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz"
         curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz.sha256sum"
         sha256sum --check hubble-linux-amd64.tar.gz.sha256sum
         tar zxf hubble-linux-amd64.tar.gz

      and move the ``hubble`` CLI to a directory listed in the ``$PATH`` environment variable. For example:

      .. parsed-literal::

         sudo mv hubble /usr/local/bin

   .. group-tab:: MacOS

      Download the latest hubble release:

      .. parsed-literal::

         export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
         curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-darwin-amd64.tar.gz"
         curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-darwin-amd64.tar.gz.sha256sum"
         shasum -a 256 -c hubble-darwin-amd64.tar.gz.sha256sum
         tar zxf hubble-darwin-amd64.tar.gz

      and move the ``hubble`` CLI to a directory listed in the ``$PATH`` environment variable. For example:

      .. parsed-literal::

         sudo mv hubble /usr/local/bin

   .. group-tab:: Windows

      Download the latest hubble release:

      .. parsed-literal::

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
