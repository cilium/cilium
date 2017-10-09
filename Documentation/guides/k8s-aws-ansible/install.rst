*Kubernetes + CoreOS + Cilium Stack building with Ansible*

IP SPACES
---------

AWS VMs 192.168.32.0/19 192.168.64.0/19 192.168.96.0/19

SERVICE\_IP\_RANGE 192.168.192.0/19 K8S\_SERVICE\_IP 192.168.192.1/19
DNS\_SERVICE\_IP 192.168.192.10/19

CILIUM 10.X.X.Y/8

2. Cluster TLS using OpenSSL
----------------------------

2.1 Kubernetes API Server Keypair
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium$ cd installation/ca/
    core@host:~/cilium/installation/caNew$ vi openssl.cnf
    [req]
    req_extensions = v3_req
    distinguished_name = req_distinguished_name
    [req_distinguished_name]
    [ v3_req ]
    basicConstraints = CA:FALSE
    keyUsage = nonRepudiation, digitalSignature, keyEncipherment
    subjectAltName = @alt_names
    [alt_names]
    DNS.1 = kubernetes
    DNS.2 = kubernetes.default
    DNS.3 = kubernetes.default.svc
    DNS.4 = kubernetes.default.svc.cluster.local
    IP.1 = 192.168.192.1
    IP.2 = x.x.x.x
    IP.3 = 192.168.192.10
    IP.4 = 192.168.32.11
    IP.5 = 192.168.32.12
    IP.6 = 192.168.32.13
    DNS.5 = api.x.x.x.x
    core@host:~/cilium/installation/caNew$ openssl genrsa -out apiserver-key.pem 2048
    Generating RSA private key, 2048 bit long modulus
    ...........................+++
    ................................................+++
    e is 65537 (0x10001)
    core@host:~/cilium/installation/caNew$ openssl req -new -key apiserver-key.pem -out apiserver.csr -subj "/CN=kube-apiserver" -config openssl.cnf
    core@host:~/cilium/installation/caNew$ openssl x509 -req -in apiserver.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out apiserver.pem -days 365 -extensions v3_req -extfile openssl.cnf
    Signature ok
    subject=/CN=kube-apiserver
    Getting CA Private Key

2.2 Kubernetes Worker Keypairs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium/installation/caNew$ vi worker-openssl.cnf
    [req]
    req_extensions = v3_req
    distinguished_name = req_distinguished_name
    [req_distinguished_name]
    [ v3_req ]
    basicConstraints = CA:FALSE
    keyUsage = nonRepudiation, digitalSignature, keyEncipherment
    subjectAltName = @alt_names
    [alt_names]
    IP.1 = 192.168.32.21
    IP.2 = 192.168.32.22
    IP.3 = 192.168.32.23
    core@host:~/cilium/installation/caNew$ 
    $ openssl genrsa -out S1-worker-key.pem 2048
    $ WORKER_IP=192.168.32.21 openssl req -new -key S1-worker-key.pem -out S1-worker.csr -subj "/CN=S1" -config worker-openssl.cnf
    $ WORKER_IP=192.168.32.21 openssl x509 -req -in S1-worker.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out S1-worker.pem -days 365 -extensions v3_req -extfile worker-openssl.cnf
    $ openssl genrsa -out S2-worker-key.pem 2048
    $ WORKER_IP=192.168.32.22 openssl req -new -key S2-worker-key.pem -out S2-worker.csr -subj "/CN=S2" -config worker-openssl.cnf
    $ WORKER_IP=192.168.32.22 openssl x509 -req -in S2-worker.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out S2-worker.pem -days 365 -extensions v3_req -extfile worker-openssl.cnf
    $ openssl genrsa -out S3-worker-key.pem 2048
    $ WORKER_IP=192.168.32.23 openssl req -new -key S3-worker-key.pem -out S3-worker.csr -subj "/CN=S3" -config worker-openssl.cnf
    $ WORKER_IP=192.168.32.23 openssl x509 -req -in S3-worker.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out S3-worker.pem -days 365 -extensions v3_req -extfile worker-openssl.cnf

2.3 Generate the Cluster Administrator Keypair
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium/installation/caNew$ openssl genrsa -out admin-key.pem 2048
    core@host:~/cilium/installation/caNew$ openssl req -new -key admin-key.pem -out admin.csr -subj "/CN=kube-admin"
    core@host:~/cilium/installation/caNew$ openssl x509 -req -in admin.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out admin.pem -days 365

2.4 Distribute the TLS certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,PublicIpAddress,Tags[0].Value,ImageId,State.Name,Placement.AvailabilityZone,LaunchTime]' --filters Name=tag:Name,Values=cilium* --output text |sort -k 4|grep -v None
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.11   x.x.x.x ciliumMaster1   ami-xxxxxxxx    running us-west-1a  2017-06-16T06:08:24.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.12   x.x.x.x ciliumMaster2   ami-xxxxxxxx    running us-west-1a  2017-06-16T06:08:24.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.13   x.x.x.x ciliumMaster3   ami-xxxxxxxx    running us-west-1a  2017-06-16T06:08:24.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.21   x.x.x.x ciliumSlave1    ami-xxxxxxxx    running us-west-1a  2017-06-16T06:08:24.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.22   x.x.x.x ciliumSlave2    ami-xxxxxxxx    running us-west-1a  2017-06-16T06:08:24.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.23   x.x.x.x ciliumSlave3    ami-xxxxxxxx    running us-west-1a  2017-06-16T06:08:24.000Z

Backup current ones first

::

    10.3.0.11       mi1
    10.3.0.12       mi2
    10.3.0.13       mi3
    10.3.0.21       si1
    10.3.0.22       si2
    10.3.0.23       si3


    x.x.x.x     mp1
    x.x.x.x     mp2
    x.x.x.x     mp3
    x.x.x.x     sp1
    x.x.x.x     sp2
    x.x.x.x     sp3

| Update hosts file
| $ sudo vi /etc/hosts

::

    192.168.32.11   mi1
    192.168.32.12   mi2
    192.168.32.13   mi3
    192.168.32.21   si1
    192.168.32.22   si2
    192.168.32.23   si3

    x.x.x.x     mp1 
    x.x.x.x     mp2 
    x.x.x.x     mp3 
    x.x.x.x     sp1 
    x.x.x.x     sp2 
    x.x.x.x     sp3

::

    core@host:~/cilium/installation/caNew$
    for host in mp1 mp2 mp3; do scp ca.pem ca-key.pem apiserver.pem apiserver-key.pem core@${host}:~/; done
    scp ca.pem S1-worker.pem S1-worker-key.pem core@sp1:~/;
    scp ca.pem S2-worker.pem S2-worker-key.pem core@sp2:~/;
    scp ca.pem S3-worker.pem S3-worker-key.pem core@sp3:~/;

4. Deploy Kubernetes Worker Node(s)
-----------------------------------

4.1 Start VMs if stopped
~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ for i in $S1 $S2 $S3; do aws ec2 start-instances --instance-ids $i; done;
    $ aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,PublicIpAddress,Tags[0].Value,ImageId,State.Name,Placement.AvailabilityZone,LaunchTime]' --filters Name=tag:Name,Values=cilium* --output text |sort -k 4|grep -v None
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.11   x.x.x.x ciliumMaster1   ami-xxxxxxxx    running us-west-1a  2017-06-29T08:43:00.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.12   x.x.x.x ciliumMaster2   ami-xxxxxxxx    running us-west-1a  2017-06-29T08:43:01.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.13   x.x.x.x ciliumMaster3   ami-xxxxxxxx    running us-west-1a  2017-06-29T08:43:03.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.21   x.x.x.x ciliumSlave1    ami-xxxxxxxx    running us-west-1a  2017-06-29T13:34:51.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.22   x.x.x.x ciliumSlave2    ami-xxxxxxxx    running us-west-1a  2017-06-29T13:34:52.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.23   x.x.x.x ciliumSlave3    ami-xxxxxxxx    running us-west-1a  2017-06-29T13:34:53.000Z

update new ips here

::

    $ sudo vi /etc/hosts
    $ vi ~/cilium/installation/ansible/hosts

4.2 TLS Assets
~~~~~~~~~~~~~~

::

    $ ansible -i hosts sps -m shell -a "ls"
    x.x.x.x | SUCCESS | rc=0 >>
    S3-worker-key.pem
    S3-worker.pem
    bin
    ca.pem
    pypy

    x.x.x.x | SUCCESS | rc=0 >>
    S1-worker-key.pem
    S1-worker.pem
    bin
    ca.pem
    pypy

    x.x.x.x | SUCCESS | rc=0 >>
    S2-worker-key.pem
    S2-worker.pem
    bin
    ca.pem
    pypy

    $ ansible -i hosts sp1 -b -m shell -a "mv S1-worker-key.pem  S1-worker.pem  ca.pem /etc/kubernetes/ssl/"
    x.x.x.x | SUCCESS | rc=0 >>

    $ ansible -i hosts sp2 -b -m shell -a "mv S2-worker-key.pem  S2-worker.pem  ca.pem /etc/kubernetes/ssl/"
    x.x.x.x | SUCCESS | rc=0 >>


    $ ansible -i hosts sp3 -b -m shell -a "mv S3-worker-key.pem  S3-worker.pem  ca.pem /etc/kubernetes/ssl/"
    x.x.x.x | SUCCESS | rc=0 >>


    $ ansible -i hosts sps -b -m shell -a "ls /etc/kubernetes/ssl/"
    x.x.x.x | SUCCESS | rc=0 >>
    S3-worker-key.pem
    S3-worker.pem
    ca.pem

    x.x.x.x | SUCCESS | rc=0 >>
    S2-worker-key.pem
    S2-worker.pem
    ca.pem

    x.x.x.x | SUCCESS | rc=0 >>
    S1-worker-key.pem
    S1-worker.pem
    ca.pem

    $ ansible -i hosts sps -b -m shell -a "sudo chmod 600 /etc/kubernetes/ssl/*-key.pem"

    $ ansible -i hosts sps -b -m shell -a "chown root:root /etc/kubernetes/ssl/*-key.pem"


    $ ansible -i hosts sp1 -b -m shell -a "ln -s /etc/kubernetes/ssl/S1-worker.pem /etc/kubernetes/ssl/worker.pem"

    $ ansible -i hosts sp2 -b -m shell -a "ln -s /etc/kubernetes/ssl/S2-worker.pem /etc/kubernetes/ssl/worker.pem"

    $ ansible -i hosts sp3 -b -m shell -a "ln -s /etc/kubernetes/ssl/S3-worker.pem /etc/kubernetes/ssl/worker.pem"



    $ ansible -i hosts sp1 -b -m shell -a "ln -s /etc/kubernetes/ssl/S1-worker-key.pem /etc/kubernetes/ssl/worker-key.pem"

    $ ansible -i hosts sp2 -b -m shell -a "ln -s /etc/kubernetes/ssl/S2-worker-key.pem /etc/kubernetes/ssl/worker-key.pem"

    $ ansible -i hosts sp3 -b -m shell -a "ln -s /etc/kubernetes/ssl/S3-worker-key.pem /etc/kubernetes/ssl/worker-key.pem"

    $ ansible -i hosts sps -b -m shell -a "ls -lah"
    x.x.x.x | SUCCESS | rc=0 >>
    total 84K
    drwxr-xr-x. 6 core core 4.0K Jun 29 13:52 .
    drwxr-xr-x. 3 root root 4.0K May 30 23:26 ..
    drwx------. 3 core core 4.0K Jun 16 09:45 .ansible
    -rw-------. 1 core core    0 Jun 14 10:46 .authorized_keys.d.lock
    lrwxrwxrwx. 1 core core   33 May 30 23:26 .bash_logout -> ../../usr/share/skel/.bash_logout
    lrwxrwxrwx. 1 core core   34 May 30 23:26 .bash_profile -> ../../usr/share/skel/.bash_profile
    lrwxrwxrwx. 1 core core   28 May 30 23:26 .bashrc -> ../../usr/share/skel/.bashrc
    -rw-r--r--. 1 core core    0 Jun 16 09:45 .bootstrapped
    drwx------. 3 core core 4.0K Jun 29 13:48 .ssh
    -rw-r--r--. 1 core core  168 Jun 16 09:45 .wget-hsts
    drwxr-xr-x. 2 core core 4.0K Jun 16 09:46 bin
    drwxr-xr-x. 8 core core 4.0K Jun 16 09:45 pypy
    lrwxrwxrwx. 1 root root   17 Jun 29 13:52 worker-key.pem -> S2-worker-key.pem
    lrwxrwxrwx. 1 root root   13 Jun 29 13:51 worker.pem -> S2-worker.pem

    x.x.x.x | SUCCESS | rc=0 >>
    total 84K
    drwxr-xr-x. 6 core core 4.0K Jun 29 13:52 .
    drwxr-xr-x. 3 root root 4.0K May 30 23:26 ..
    drwx------. 3 core core 4.0K Jun 16 09:45 .ansible
    -rw-------. 1 core core    0 Jun 14 10:46 .authorized_keys.d.lock
    lrwxrwxrwx. 1 core core   33 May 30 23:26 .bash_logout -> ../../usr/share/skel/.bash_logout
    lrwxrwxrwx. 1 core core   34 May 30 23:26 .bash_profile -> ../../usr/share/skel/.bash_profile
    lrwxrwxrwx. 1 core core   28 May 30 23:26 .bashrc -> ../../usr/share/skel/.bashrc
    -rw-r--r--. 1 core core    0 Jun 16 09:45 .bootstrapped
    drwx------. 3 core core 4.0K Jun 29 13:35 .ssh
    -rw-r--r--. 1 core core  168 Jun 16 09:45 .wget-hsts
    drwxr-xr-x. 2 core core 4.0K Jun 16 09:46 bin
    drwxr-xr-x. 8 core core 4.0K Jun 16 09:45 pypy
    lrwxrwxrwx. 1 root root   17 Jun 29 13:52 worker-key.pem -> S1-worker-key.pem
    lrwxrwxrwx. 1 root root   13 Jun 29 13:51 worker.pem -> S1-worker.pem

    x.x.x.x | SUCCESS | rc=0 >>
    total 84K
    drwxr-xr-x. 6 core core 4.0K Jun 29 13:52 .
    drwxr-xr-x. 3 root root 4.0K May 30 23:26 ..
    drwx------. 3 core core 4.0K Jun 16 09:45 .ansible
    -rw-------. 1 core core    0 Jun 14 10:46 .authorized_keys.d.lock
    lrwxrwxrwx. 1 core core   33 May 30 23:26 .bash_logout -> ../../usr/share/skel/.bash_logout
    lrwxrwxrwx. 1 core core   34 May 30 23:26 .bash_profile -> ../../usr/share/skel/.bash_profile
    lrwxrwxrwx. 1 core core   28 May 30 23:26 .bashrc -> ../../usr/share/skel/.bashrc
    -rw-r--r--. 1 core core    0 Jun 16 09:45 .bootstrapped
    drwx------. 3 core core 4.0K Jun 29 13:35 .ssh
    -rw-r--r--. 1 core core  168 Jun 16 09:45 .wget-hsts
    drwxr-xr-x. 2 core core 4.0K Jun 16 09:46 bin
    drwxr-xr-x. 8 core core 4.0K Jun 16 09:45 pypy
    lrwxrwxrwx. 1 root root   17 Jun 29 13:52 worker-key.pem -> S3-worker-key.pem
    lrwxrwxrwx. 1 root root   13 Jun 29 13:51 worker.pem -> S3-worker.pem

4.3 Create and run ansible playbook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium/installation/ansible/roles/slaves/tasks$ vi main.yml 
    - name: template_kubelet.service
      hosts: sps
      become: true
      remote_user: core
      handlers: 
        - include: ../handlers/main.yml
      tasks:

        - name: slave main.yml | Templating out kubelet.service script 
          template:
           src: ../templates/kubelet.service.j2
           dest: /etc/systemd/system/kubelet.service
           owner: root
           group: root
           mode: 0644
          notify: restart kubelet.service

        - name: slave main.yml | Creates directory /etc/kubernetes/manifests
          file: 
           path: /etc/kubernetes/manifests
           state: directory

        - name: slave main.yml | Creates directory /etc/cni/net.d
          file:
           path: /etc/cni/net.d
           state: directory

        - name: slave main.yml | Make sure kubelet.service is running and enabled
          systemd: name=kubelet.service state=started enabled=yes

        - name: slave main.yml | Templating out worker-kubeconfig.yaml script
          template:
           src: ../templates/worker-kubeconfig.yaml.j2
           dest: /etc/kubernetes/worker-kubeconfig.yaml
           owner: root
           group: root
    #
        - name: slave main.yml | Creates directory /opt/cni
          file:
           path: /opt/cni
           state: directory

        - name: slave main.yml | Download cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
          get_url:
           url: https://storage.googleapis.com/kubernetes-release/network-plugins/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
           dest: /home/core/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
           mode: 0440

        - name: slave main.yml | Extract cni archive
          unarchive:
           src: /home/core/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
           dest: /opt/cni
           remote_src: True
    #       extra_opts: [--strip-components=1]

        - name: slave main.yml | Creates directory /opt/bin
          file:
           path: /opt/bin
           state: directory

        - name: slave main.yml | Download kubectl
          get_url:
           url: https://storage.googleapis.com/kubernetes-release/release/v1.6.6/bin/linux/amd64/kubectl
           dest: /opt/bin/kubectl
           mode: 0740

        - name: slave main.yml | Change the owner of kubectl to core
          file:
           path: /opt/bin/kubectl
           owner: core
           group: core
           mode: 0740

::

    core@host:~/cilium/installation/ansible$ ansible-playbook -i hosts roles/slaves/tasks/main.yml

    PLAY [template_kubelet.service] **********************************************************************************************************************************************************************************

    TASK [Gathering Facts] *******************************************************************************************************************************************************************************************
    ok: [x.x.x.x]
    ok: [x.x.x.x]
    ok: [x.x.x.x]

    TASK [slave main.yml | Templating out kubelet.service script] ****************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Creates directory /etc/kubernetes/manifests] **********************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Creates directory /etc/cni/net.d] *********************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Make sure kubelet.service is running and enabled] *****************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Templating out worker-kubeconfig.yaml script] *********************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Creates directory /opt/cni] ***************************************************************************************************************************************************************
    ok: [x.x.x.x]
    ok: [x.x.x.x]
    ok: [x.x.x.x]

    TASK [slave main.yml | Download cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz] *****************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Extract cni archive] **********************************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Creates directory /opt/bin] ***************************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Download kubectl] *************************************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    TASK [slave main.yml | Change the owner of kubectl to core] ******************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    RUNNING HANDLER [restart kubelet.service] ************************************************************************************************************************************************************************
    changed: [x.x.x.x]
    changed: [x.x.x.x]
    changed: [x.x.x.x]

    PLAY RECAP *******************************************************************************************************************************************************************************************************
    x.x.x.x              : ok=13   changed=11   unreachable=0    failed=0   
    x.x.x.x               : ok=13   changed=11   unreachable=0    failed=0   
    x.x.x.x             : ok=13   changed=11   unreachable=0    failed=0  

--------------

5. Setting up kubectl
---------------------

::

    core@host:~/cilium/installation/caNew$ env |grep kube
    KUBECONFIG=/home/core/cilium/installation/.kube/config

    core@host:~/cilium/installation$ cd caNew/
    core@host:~/cilium/installation/caNew$ kubectl config set-cluster default-cluster --server=http://api.x.x.x.x:8080 --certificate-authority=ca.pem
    Cluster "default-cluster" set.
    core@host:~/cilium/installation/caNew$ kubectl config set-credentials default-admin --certificate-authority=ca.pem --client-key=admin-key.pem --client-certificate=admin.pem
    User "default-admin" set.
    core@host:~/cilium/installation/caNew$ kubectl config set-context default-system --cluster=default-cluster --user=default-admin
    Context "default-system" set.
    core@host:~/cilium/installation/caNew$ cat ../.kube/config 
    apiVersion: v1
    clusters:
    - cluster:
        certificate-authority: /home/core/cilium/installation/caNew/ca.pem
        server: http://api.x.x.x.x:8080
      name: default-cluster
    contexts:
    - context:
        cluster: default-cluster
        user: default-admin
      name: default-system
    current-context: ""
    kind: Config
    preferences: {}
    users:
    - name: default-admin
      user:
        client-certificate: /home/core/cilium/installation/caNew/admin.pem
        client-key: /home/core/cilium/installation/caNew/admin-key.pem
    core@host:~/cilium/installation/caNew$ kubectl config use-context default-system
    Switched to context "default-system".
    core@host:~/cilium/installation/caNew$ kubectl get nodes
    NAME            STATUS                     AGE       VERSION
    192.168.32.11   Ready,SchedulingDisabled   12d       v1.6.4+coreos.0
    192.168.32.12   Ready,SchedulingDisabled   12d       v1.6.4+coreos.0
    192.168.32.13   Ready,SchedulingDisabled   12d       v1.6.4+coreos.0
    192.168.32.21   Ready                      27m       v1.6.4+coreos.0
    192.168.32.22   Ready                      27m       v1.6.4+coreos.0
    192.168.32.23   Ready                      27m       v1.6.4+coreos.0
    core@host:~/cilium/installation/caNew$ kubectl get pods --all-namespaces
    NAMESPACE     NAME                                    READY     STATUS    RESTARTS   AGE
    kube-system   cilium-780nq                            1/1       Running   0          12m
    kube-system   cilium-cdn08                            1/1       Running   0          12m
    kube-system   cilium-consul-7tlnk                     1/1       Running   0          12m
    kube-system   cilium-consul-wtf9g                     1/1       Running   0          12m
    kube-system   cilium-consul-zdt65                     1/1       Running   0          12m
    kube-system   cilium-ctsvj                            1/1       Running   0          12m
    kube-system   kube-apiserver-192.168.32.11            1/1       Running   2          12d
    kube-system   kube-apiserver-192.168.32.12            1/1       Running   1          12d
    kube-system   kube-apiserver-192.168.32.13            1/1       Running   2          12d
    kube-system   kube-controller-manager-192.168.32.11   1/1       Running   2          12d
    kube-system   kube-controller-manager-192.168.32.12   1/1       Running   1          12d
    kube-system   kube-controller-manager-192.168.32.13   1/1       Running   2          12d
    kube-system   kube-scheduler-192.168.32.11            1/1       Running   2          12d
    kube-system   kube-scheduler-192.168.32.12            1/1       Running   2          12d
    kube-system   kube-scheduler-192.168.32.13            1/1       Running   3          12d

6. Deploy the DNS Add-on
------------------------

$ vi kube-dns.yml $ kubectl create -f dns-addon.yml

$ vi kube-dashboard.yaml $ kubectl create -f kube-dashboard-svc.yaml $
kubectl port-forward kubernetes-dashboard-v1.6.0-SOME-ID 9090
--namespace=kube-system