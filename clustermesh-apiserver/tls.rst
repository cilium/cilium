Create TLS Secrets for External Workloads using cilium-certgen
==============================================================

Create TLS secrets into your k8s cluster:

.. code-block:: shell-session

    $ cilium-certgen --k8s-kubeconfig-path ~/.kube/config

This takes care of the TLS config on your k8s cluster, but external
workloads need TLS config too. To this end, Cilium Agent in the VM
needs to be configured with the following options:

::

    --join-cluster --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml

``/var/lib/cilium/etcd/config.yaml`` in the VM needs to contain the following config:

.. code-block:: yaml

    trusted-ca-file: /var/lib/cilium/etcd/ca.crt
    cert-file: /var/lib/cilium/etcd/tls.crt
    key-file: /var/lib/cilium/etcd/tls.key
    endpoints:
    - https://clustermesh-apiserver.cilium.io:32379

Certificate files in ``/var/lib/cilium/etcd/`` can be extracted from the k8s secrets created above:

.. code-block:: shell-session

    $ kubectl -n kube-system get secret externalworkload-client-certs -o jsonpath="{.data['ca\.crt']}" | base64 --decode >ca.crt
    $ kubectl -n kube-system get secret externalworkload-client-certs -o jsonpath="{.data['tls\.crt']}" | base64 --decode >tls.crt
    $ kubectl -n kube-system get secret externalworkload-client-certs -o jsonpath="{.data['tls\.key']}" | base64 --decode >tls.key

Alternatively, all the secrets can be created manually using openssl as instructed below.

Finally, add ``clustermesh-apiserver.cilium.io`` into ``/etc/hosts``,
using an externally accessible service IP from your cluster:

::

    192.168.56.11 clustermesh-apiserver.cilium.io

Manual instructions using openssl
=================================

Create an Internal Certificate Authority (CA)
---------------------------------------------

.. code-block:: shell-session

    $ openssl req -nodes -new -x509 -keyout VMCA.key -sha256 -days 1825 -out VMCA.crt -subj '/CN=clustermesh-apiserver-ca.cilium.io'

Generate CA private key named 'VMCA.key':

.. code-block:: shell-session

    $ openssl genrsa -des3 -out VMCA.key 2048

Enter any password, just remember it for some of the later steps.

Generate CA certificate from the private key:

.. code-block:: shell-session

    $ openssl req -x509 -new -nodes -key VMCA.key -sha256 -days 1825 -out VMCA.crt

The values you enter for each prompt do not need to be any specific value, and do not need to be
accurate.

Create Private Key and Certificate Signing Request for clustermesh-apiserver
----------------------------------------------------------------------------

Generate an internal private key for clustermesh-apiserver

First create the private key:

.. code-block:: shell-session

    $ openssl genrsa -out clustermesh-apiserver.key 2048

Next, create a certificate signing request:

.. code-block:: shell-session

    $ openssl req -new -key clustermesh-apiserver.key -out clustermesh-apiserver.csr -subj '/CN=clustermesh-apiserver.cilium.io'

.. note::

    You may need to comment out the ``RANDFILE              = $ENV::HOME/.rnd`` line from ``/etc/ssl/openssl.cnf`` for this to work.


Use the internal CA private key to create a signed certificate:

.. code-block:: shell-session

    $ openssl x509 -req -days 360 -in clustermesh-apiserver.csr -CA VMCA.crt -CAkey VMCA.key -CAcreateserial \
      -out clustermesh-apiserver.crt -sha256 \
      -extfile <(printf "extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:clustermesh-apiserver.cilium.io,IP:127.0.0.1")

Next we create a Kubernetes secret that includes both the CA certificate,
and private key and signed certificates for clustermesh-apiserver:

.. code-block:: shell-session

    $ kubectl create secret generic externalworkload-server-certs -n kube-system \
      --from-file=ca.crt=VMCA.crt \
      --from-file=tls.crt=clustermesh-apiserver.crt \
      --from-file=tls.key=clustermesh-apiserver.key

Create Private Key and Certificate Signing Request for clustermesh-apiserver-admin
----------------------------------------------------------------------------------

Generate an internal private key for clustermesh-apiserver

First create the private key:

.. code-block:: shell-session

    $ openssl genrsa -out clustermesh-apiserver-admin.key 2048

Next, create a certificate signing request:

.. code-block:: shell-session

    $ openssl req -new -key clustermesh-apiserver-admin.key -out clustermesh-apiserver-admin.csr -subj '/CN=root'

.. note::

    You may need to comment out the ``RANDFILE              = $ENV::HOME/.rnd`` line from ``/etc/ssl/openssl.cnf`` for this to work.


Use the internal CA private key to create a signed certificate:

.. code-block:: shell-session

    $ openssl x509 -req -days 360 -in clustermesh-apiserver-admin.csr -CA VMCA.crt -CAkey VMCA.key -CAcreateserial \
      -out clustermesh-apiserver-admin.crt -sha256 \
      -extfile <(printf "extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:localhost")

Next we create a Kubernetes secret that includes both the CA certificate,
and private key and signed certificates for clustermesh-apiserver-admin:

.. code-block:: shell-session

    $ kubectl create secret generic externalworkload-admin-certs -n kube-system \
      --from-file=ca.crt=VMCA.crt \
      --from-file=tls.crt=clustermesh-apiserver-admin.crt \
      --from-file=tls.key=clustermesh-apiserver-admin.key

Create Private Key and Certificate for a VM
-------------------------------------------

Generate an internal private key for VM "runtime"

First create the private key:

.. code-block:: shell-session

    $ openssl genrsa -out client.key 2048

Next, create a certificate signing request:

.. code-block:: shell-session

    $ openssl req -new -key client.key -out client.csr -subj '/CN=externalworkload'

Use the internal CA private key to create a signed certificate:

.. code-block:: shell-session

    $ openssl x509 -req -days 360 -in client.csr -CA VMCA.crt -CAkey VMCA.key -CAcreateserial \
      -out client.crt -sha256 \
      -extfile <(printf "extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:externalworkload")

Next we store the client certificate as a Kubernetes secret that includes both the CA certificate,
and private key and signed certificates for clustermesh-apiserver-client:

.. code-block:: shell-session

    $ kubectl create secret generic externalworkload-client-certs -n kube-system \
      --from-file=ca.crt=VMCA.crt \
      --from-file=tls.crt=client.crt \
      --from-file=tls.key=client.key

Configure Cilium agent on the VM
--------------------------------

Cilium Agent in the VM needs to be configured with the following options:

::

    --join-cluster --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml

Create ``/var/lib/cilium/etcd/config.yaml`` with the following contents:

.. code-block:: yaml

    ---
    trusted-ca-file: /var/lib/cilium/etcd/ca.crt
    cert-file: /var/lib/cilium/etcd/tls.crt
    key-file: /var/lib/cilium/etcd/tls.key
    endpoints:
    - https://clustermesh-apiserver.cilium.io:32379

Place the certificates into ``/var/lib/cilium/etcd`` in the VM:

.. code-block:: shell-session

    $ cp VMCA.crt /var/lib/cilium/etcd/ca.crt
    $ cp client.crt /var/lib/cilium/etcd/tls.crt
    $ cp client.key /var/lib/cilium/etcd/tls.key

Finally, add ``clustermesh-apiserver.cilium.io`` into ``/etc/hosts`` using an
externally accessible service IP from your cluster:

::

    192.168.56.11 clustermesh-apiserver.ciliumn.io

Starting Cilium in a Container in a VM
======================================

$ docker run -d --name cilium --restart always --privileged --cap-add ALL --log-driver syslog cilium/cilium-dev:testing  


--volume /home/vagrant/cilium/etcd:/var/lib/cilium/etcd


/usr/bin/cilium-agent --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml --ipv4-node 192.168.56.10 --join-cluster
sudo mount bpffs -t bpf /sys/fs/bpf

--add-host clustermesh-apiserver.cilium.io:192.168.56.11
--network host
--privileged
--cap-add ALL
--name cilium
--rm
--volume /var/lib/cilium/etcd:/var/lib/cilium/etcd
