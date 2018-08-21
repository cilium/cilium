.. _admin_install_source:

*************************
Installation From Source
*************************

If for some reason you do not want to run Cilium as a container image.
Installing it from source is possible as well. It does come with additional
dependencies described in :ref:`admin_system_reqs`.

0. Requirements:

Install go-bindata:

.. code:: bash

   $ go get -u github.com/cilium/go-bindata/...

Add $GOPATH/bin to your $PATH:

.. code:: bash

   $ # To add $GOPATH/bin in your $PATH run
   $ export PATH=$GOPATH/bin:$PATH

You can also add it in your ``~/.bashrc`` file:

.. code:: bash

   if [ -d $GOPATH/bin ]; then
       export PATH=$PATH:$GOPATH/bin
   fi

1. Download & extract the latest Cilium release from the ReleasesPage_

.. _ReleasesPage: https://github.com/cilium/cilium/releases

.. code:: bash

   $ go get -d github.com/cilium/cilium
   $ cd $GOPATH/src/github.com/cilium/cilium

2. Build & install the Cilium binaries to ``bindir``

.. code:: bash

   $ git checkout v0.11
   $ # We are pointing to $GOPATH/bin as well since it's where go-bindata is
   $ # installed
   $ make
   $ sudo make install

3. Optional: Install systemd init files:

.. code:: bash

    sudo cp contrib/systemd/*.service /lib/systemd/system
    sudo cp contrib/systemd/sys-fs-bpf.mount /lib/systemd/system
    sudo mkdir -p /etc/sysconfig/cilium && cp contrib/systemd/cilium /etc/sysconfig/cilium
    service cilium start
