*Kubernetes + CoreOS + Cilium Stack building with Ansible*

IP SPACES
---------

AWS VMs 

::
    192.168.32.0/19 
    192.168.64.0/19 
    192.168.96.0/19

SERVICE\_IP\_RANGE 

::

    192.168.192.0/19 

K8S\_SERVICE\_IP 

::

    192.168.192.1/19
DNS\_SERVICE\_IP 

::

    192.168.192.10/19

CILIUM 

::

    10.X.X.Y/8

1. Getting started with AWS
----------------------------

1.1 Create new vpc and network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium$ mkdir installation;cd installation/
    core@host:~/cilium$ aws ec2 create-vpc --cidr-block 192.168.32.0/19
    core@host:~/cilium/installation$ export VPC_ID=vpc-xxxxxxxx
    core@host:~/cilium/installation$ aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 192.168.32.0/19
    core@host:~/cilium/installation$ export SUBNET_ID=subnet-xxxxxxxx
    core@host:~/cilium/installation$ aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch
    core@host:~/cilium/installation$ aws ec2 create-internet-gateway
    core@host:~/cilium/installation$ export GATEWAY_ID=igw-xxxxxxxx
    core@host:~/cilium/installation$ aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway $GATEWAY_ID
    core@host:~/cilium/installation$ aws ec2 create-route-table --vpc-id $VPC_ID
    core@host:~/cilium/installation$ export ROUTE_TABLE_ID=rtb-xxxxxxxx
    core@host:~/cilium/installation$ aws ec2 associate-route-table --subnet-id $SUBNET_ID --route-table-id $ROUTE_TABLE_ID
    core@host:~/cilium/installation$ aws ec2 create-route --route-table-id $ROUTE_TABLE_ID --destination-cidr-block 0.0.0.0/0     --gateway-id $GATEWAY_ID
    core@host:~/cilium/installation$ aws ec2 modify-vpc-attribute --vpc-id=$VPC_ID --enable-dns-support
    core@host:~/cilium/installation$ aws ec2 modify-vpc-attribute --vpc-id=$VPC_ID --enable-dns-hostnames

1.2 Configuring Key Pair and Security Group 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium/installation$ aws ec2 create-key-pair --key-name key --query 'KeyMaterial' --output text > key.pem
    core@host:~/cilium/installation$ chmod 400 key.pem
    core@host:~/cilium/installation$ aws ec2 create-security-group --group-name SG --description SG --vpc-id $VPC_ID
    core@host:~/cilium/installation$ export SECURITY_GROUP_ID=sg-xxxxxxxx
    core@host:~/cilium/installation$ aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --protocol tcp --port 22     --cidr x.x.x.x/8
    core@host:~/cilium/installation$ aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --protocol tcp --port 22     --cidr x.x.x.x/32
    core@host:~/cilium/installation$ aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --source-group     $SECURITY_GROUP_ID  --protocol all --port all

1.3 Spinning up the VMs  
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    core@host:~/cilium/installation$ export IMAGE_ID=ami-xxxxxxxx
    core@host:~/cilium/installation$ aws ec2 describe-images --image-ids ami-xxxxxxxx


1.3.1 CREATE MASTERS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    core@host:~/cilium/installation$ wget https://github.com/coreos/container-linux-config-transpiler/releases/download/v0.3.1/    ct-v0.3.1-x86_64-unknown-linux-gnu
    core@host:~/cilium/installation$ chmod +x ct-v0.3.1-x86_64-unknown-linux-gnu

::

    core@host:~/cilium/installation$ vi master-config.yaml
    # This config is meant to be consumed by the config transpiler, which will
    # generate the corresponding Ignition config. Do not pass this config directly
    # to instances of Container Linux.
    
              etcd:
                # All options get passed as command line flags to etcd.
                # Any information inside curly braces comes from the machine at boot time.
              
                # multi_region and multi_cloud deployments need to use {PUBLIC_IPV4}
                advertise_client_urls:       "http://{PRIVATE_IPV4}:2379"
                initial_advertise_peer_urls: "http://{PRIVATE_IPV4}:2380"
                # listen on both the official ports and the legacy ports
                # legacy ports can be omitted if your application doesn't depend on them
                listen_client_urls:          "http://0.0.0.0:2379"
                listen_peer_urls:            "http://{PRIVATE_IPV4}:2380"
                # generate a new token for each unique cluster from https://discovery.etcd.io/new?size=3
                # specify the initial size of your cluster with ?size=X
                discovery:                   "https://discovery.etcd.io/XXXXXXXXXXXXXXXXXXXXXXXXXXXX"

::

    core@host:~/cilium/installation$ ./ct-v0.3.1-x86_64-unknown-linux-gnu --platform=ec2 --pretty --in-file master-config.yaml >     master-config.json
    core@host:~/cilium/installation$ cat master-config.json
    {
      "ignition": {
        "version": "2.0.0",
        "config": {}
      },
      "storage": {},
      "systemd": {
        "units": [
          {
            "name": "etcd-member.service",
            "enable": true,
            "dropins": [
              {
                "name": "20-clct-etcd-member.conf",
                "contents": "[Unit]\nRequires=coreos-metadata.service\nAfter=coreos-metadata.service\n\n[Service]\nEnvironmentFile=/run/    metadata/coreos\nExecStart=\nExecStart=/usr/lib/coreos/etcd-wrapper $ETCD_OPTS \\\n      --listen-peer-urls=\"http://${COREOS_EC2_IPV4_LOCAL}:2380\" \\\n  --listen-client-urls=\"http://0.0.0.0:2379\" \\\n      --initial-advertise-peer-urls=\"http://${COREOS_EC2_IPV4_LOCAL}:2380\" \\\n      --advertise-client-urls=\"http://${COREOS_EC2_IPV4_LOCAL}:2379\" \\\n  --discovery=\"https://discovery.etcd.io/    XXXXXXXXXXXXXXXXXXXXXXXXXXXX\""
              }
            ]
          }
        ]
      },
      "networkd": {},
      "passwd": {}
    }        

::


    M1=`aws ec2 run-instances --image-id $IMAGE_ID --instance-type m3.medium --key-name key --security-group-ids $SECURITY_GROUP_ID     --subnet $SUBNET_ID --private-ip-address 192.168.32.11 --block-device-mappings="[{\"DeviceName\":\"/dev/    xvda\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":50,\"VolumeType\":\"gp2\"}}]" --user-data file://master-config.json |grep     InstanceId|awk -F'"' '{print $4}'`
    
    M2=`aws ec2 run-instances --image-id $IMAGE_ID --instance-type m3.medium --key-name key --security-group-ids $SECURITY_GROUP_ID     --subnet $SUBNET_ID --private-ip-address 192.168.32.12 --block-device-mappings="[{\"DeviceName\":\"/dev/    xvda\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":50,\"VolumeType\":\"gp2\"}}]" --user-data file://master-config.json |grep     InstanceId|awk -F'"' '{print $4}'`
    
    M3=`aws ec2 run-instances --image-id $IMAGE_ID --instance-type m3.medium --key-name key --security-group-ids $SECURITY_GROUP_ID     --subnet $SUBNET_ID --private-ip-address 192.168.32.13 --block-device-mappings="[{\"DeviceName\":\"/dev/    xvda\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":50,\"VolumeType\":\"gp2\"}}]" --user-data file://master-config.json |grep     InstanceId|awk -F'"' '{print $4}'`


1.3.2 CREATE SLAVES 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    S1=`aws ec2 run-instances --image-id $IMAGE_ID --instance-type m4.large --key-name key --security-group-ids $SECURITY_GROUP_ID     --subnet $SUBNET_ID --private-ip-address 192.168.32.21 --block-device-mappings="[{\"DeviceName\":\"/dev/    xvda\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":50,\"VolumeType\":\"gp2\"}}]" |grep InstanceId|awk -F'"' '{print $4}'`
    
    S2=`aws ec2 run-instances --image-id $IMAGE_ID --instance-type m4.large --key-name key --security-group-ids $SECURITY_GROUP_ID     --subnet $SUBNET_ID --private-ip-address 192.168.32.22 --block-device-mappings="[{\"DeviceName\":\"/dev/    xvda\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":50,\"VolumeType\":\"gp2\"}}]" | grep InstanceId|awk -F'"' '{print $4}'`
    
    S3=`aws ec2 run-instances --image-id $IMAGE_ID --instance-type m4.large --key-name key --security-group-ids $SECURITY_GROUP_ID     --subnet $SUBNET_ID --private-ip-address 192.168.32.23 --block-device-mappings="[{\"DeviceName\":\"/dev/    xvda\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":50,\"VolumeType\":\"gp2\"}}]" | grep InstanceId|awk -F'"' '{print $4}'`

::

    core@host:~/cilium/installation$ for i in $M1 $M2 $M3 $S1 $S2 $S3; do echo $i;done
    i-xxxxxxxxxxxxxxxxxxx
    i-xxxxxxxxxxxxxxxxxxx
    i-xxxxxxxxxxxxxxxxxxx
    i-xxxxxxxxxxxxxxxxxxx
    i-xxxxxxxxxxxxxxxxxxx
    i-xxxxxxxxxxxxxxxxxxx
    
    echo $M1
    echo $M2
    echo $M3
    echo $S1
    echo $S2
    echo $S3

::

    core@host:~/cilium/installation$ echo $M1
    i-xxxxxxxxxxxxxxxxxxx
    core@host:~/cilium/installation$ echo $M2
    i-xxxxxxxxxxxxxxxxxxx
    core@host:~/cilium/installation$ echo $M3
    i-xxxxxxxxxxxxxxxxxxx
    core@host:~/cilium/installation$ echo $S1
    i-xxxxxxxxxxxxxxxxxxx
    core@host:~/cilium/installation$ echo $S2
    i-xxxxxxxxxxxxxxxxxxx
    core@host:~/cilium/installation$ echo $S3
    i-xxxxxxxxxxxxxxxxxxx

::

    echo "export M1=i-xxxxxxxxxxxxxxxxxxx" >> gocilium.sh
    echo "export M2=i-xxxxxxxxxxxxxxxxxxx" >> gocilium.sh
    echo "export M3=i-xxxxxxxxxxxxxxxxxxx" >> gocilium.sh
    echo "export S1=i-xxxxxxxxxxxxxxxxxxx" >> gocilium.sh
    echo "export S2=i-xxxxxxxxxxxxxxxxxxx" >> gocilium.sh
    echo "export S3=i-xxxxxxxxxxxxxxxxxxx" >> gocilium.sh


1.3.3 tag VMs 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    core@host:~/cilium/installation$ 
    aws ec2 create-tags --resources $M1 --tags Key=Name,Value=ciliumMaster1
    aws ec2 create-tags --resources $M1 --tags Key=role,Value=master
    aws ec2 modify-instance-attribute --instance-id $M1 --source-dest-check "{\"Value\": false}"
    
    aws ec2 create-tags --resources $M2 --tags Key=Name,Value=ciliumMaster2
    aws ec2 create-tags --resources $M2 --tags Key=role,Value=master
    aws ec2 modify-instance-attribute --instance-id $M2 --source-dest-check "{\"Value\": false}"
    
    aws ec2 create-tags --resources $M3 --tags Key=Name,Value=ciliumMaster3
    aws ec2 create-tags --resources $M3 --tags Key=role,Value=master
    aws ec2 modify-instance-attribute --instance-id $M3 --source-dest-check "{\"Value\": false}"

::

    core@host:~/cilium/installation$ 
    aws ec2 create-tags --resources $S1 --tags Key=Name,Value=ciliumSlave1
    aws ec2 create-tags --resources $S1 --tags Key=role,Value=slave
    aws ec2 modify-instance-attribute --instance-id $S1 --source-dest-check "{\"Value\": false}"
    
    aws ec2 create-tags --resources $S2 --tags Key=Name,Value=ciliumSlave2
    aws ec2 create-tags --resources $S2 --tags Key=role,Value=slave
    aws ec2 modify-instance-attribute --instance-id $S2 --source-dest-check "{\"Value\": false}"
    
    aws ec2 create-tags --resources $S3 --tags Key=Name,Value=ciliumSlave3
    aws ec2 create-tags --resources $S3 --tags Key=role,Value=slave
    aws ec2 modify-instance-attribute --instance-id $S3 --source-dest-check "{\"Value\": false}"

::

    $ aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,PublicIpAddress,Tags[    0].Value,ImageId,State.Name,Placement.AvailabilityZone,LaunchTime]' --filters Name=tag:Name,Values=cilium* --output text |sort -k     4|grep -v None
    
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.11   x.x.x.x ciliumMaster1   ami-xxxxxxxx    running us-west-1a  2017-06-15T13:02:34.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.12   x.x.x.x ciliumMaster2   ami-xxxxxxxx    running us-west-1a  2017-06-15T13:02:34.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.13   x.x.x.x ciliumMaster3   ami-xxxxxxxx    running us-west-1a  2017-06-15T13:02:34.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.21   x.x.x.x ciliumSlave1    ami-xxxxxxxx    running us-west-1a  2017-06-15T13:02:34.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.22   x.x.x.x ciliumSlave2    ami-xxxxxxxx    running us-west-1a  2017-06-15T13:02:34.000Z
    i-xxxxxxxxxxxxxxxxxxx   192.168.32.23   x.x.x.x ciliumSlave3    ami-xxxxxxxx    running us-west-1a  2017-06-15T13:02:34.000Z



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

3. Deploy Kubernetes Master Node(s)]
-----------------------------------

3.1 Set up ANSIBLE
~~~~~~~~~~~~~~~~~~~~~~~~

::

core@host:~/cilium/installation$ mkdir ansible;cd ansible/;
core@host:~/cilium/installation/ansible$ vi hosts
[mps:children]
mp1
mp2
mp3

[sps:children]
sp1
sp2
sp3

[mis:children]
mi1
mi2
mi3

[sis:children]
si1
si2
si3

[mi1]
192.168.32.11
[mi2]       
192.168.32.12
[mi3]       
192.168.32.13
[si1]       
192.168.32.21
[si2]       
192.168.32.22
[si3]       
192.168.32.23   

[mp1]
x.x.x.x
[mp2]     
x.x.x.x
[mp3]    
x.x.x.x
[sp1]    
x.x.x.x
[sp2]      
x.x.x.x
[sp3]     
x.x.x.x 
core@host:~/cilium/installation/ansible$ ansible-playbook -i hosts site.yml

PLAY [mps,sps] *************************************************************************************************************************************************************

TASK [defunctzombie.coreos-bootstrap : Check if bootstrap is needed] *******************************************************************************************************
fatal: [x.x.x.x]: FAILED! => {"changed": true, "failed": true, "rc": 1, "stderr": "Shared connection to x.x.x.x closed.\r\n", "stdout": "stat: cannot stat '/home/coy\r\n", "stdout_lines": ["stat: cannot stat '/home/core/.bootstrapped': No such file or directory"]}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": true, "failed": true, "rc": 1, "stderr": "Shared connection to x.x.x.x closed.\r\n", "stdout": "stat: cannot stat '/home/ory\r\n", "stdout_lines": ["stat: cannot stat '/home/core/.bootstrapped': No such file or directory"]}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": true, "failed": true, "rc": 1, "stderr": "Shared connection to x.x.x.x closed.\r\n", "stdout": "stat: cannot stat '/home/coy\r\n", "stdout_lines": ["stat: cannot stat '/home/core/.bootstrapped': No such file or directory"]}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": true, "failed": true, "rc": 1, "stderr": "Shared connection to x.x.x.x closed.\r\n", "stdout": "stat: cannot stat '/hrectory\r\n", "stdout_lines": ["stat: cannot stat '/home/core/.bootstrapped': No such file or directory"]}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": true, "failed": true, "rc": 1, "stderr": "Shared connection to x.x.x.x closed.\r\n", "stdout": "stat: cannot stat '/home/coy\r\n", "stdout_lines": ["stat: cannot stat '/home/core/.bootstrapped': No such file or directory"]}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": true, "failed": true, "rc": 1, "stderr": "Shared connection to x.x.x.x closed.\r\n", "stdout": "stat: cannot stat '/homctory\r\n", "stdout_lines": ["stat: cannot stat '/home/core/.bootstrapped': No such file or directory"]}
...ignoring

TASK [defunctzombie.coreos-bootstrap : Run bootstrap.sh] *******************************************************************************************************************
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]

TASK [defunctzombie.coreos-bootstrap : Check if we need to install pip] ****************************************************************************************************
fatal: [x.x.x.x]: FAILED! => {"changed": false, "cmd": "/home/core/bin/python -m pip --version", "delta": "0:00:00.036679", "end": "2017-06-16 09:45:31.389137", "failed5:31.352458", "stderr": "/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/n information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version information available (required by /e/pypy/bin/pypy: No module named pip", "stderr_lines": ["/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version re/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: No module named pip"], "stdout": "", "stdout_lines": []}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": false, "cmd": "/home/core/bin/python -m pip --version", "delta": "0:00:00.039126", "end": "2017-06-16 09:45:31.406716", "failed5:31.367590", "stderr": "/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/n information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version information available (required by /e/pypy/bin/pypy: No module named pip", "stderr_lines": ["/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version re/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: No module named pip"], "stdout": "", "stdout_lines": []}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": false, "cmd": "/home/core/bin/python -m pip --version", "delta": "0:00:00.082160", "end": "2017-06-16 09:45:31.791004", "fai9:45:31.708844", "stderr": "/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pysion information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version information available (required bcore/pypy/bin/pypy: No module named pip", "stderr_lines": ["/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/py: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no versi/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: No module named pip"], "stdout": "", "stdout_lines": []}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": false, "cmd": "/home/core/bin/python -m pip --version", "delta": "0:00:00.091343", "end": "2017-06-16 09:45:31.803330", "failed5:31.711987", "stderr": "/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/n information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version information available (required by /e/pypy/bin/pypy: No module named pip", "stderr_lines": ["/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version re/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: No module named pip"], "stdout": "", "stdout_lines": []}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": false, "cmd": "/home/core/bin/python -m pip --version", "delta": "0:00:00.098322", "end": "2017-06-16 09:45:31.938883", "faile45:31.840561", "stderr": "/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypyon information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version information available (required by re/pypy/bin/pypy: No module named pip", "stderr_lines": ["/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bi: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no versionore/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: No module named pip"], "stdout": "", "stdout_lines": []}
...ignoring
fatal: [x.x.x.x]: FAILED! => {"changed": false, "cmd": "/home/core/bin/python -m pip --version", "delta": "0:00:00.039747", "end": "2017-06-16 09:45:35.126427", "fail:45:35.086680", "stderr": "/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypion information available (required by /home/core/pypy/bin/libpypy-c.so)\n/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no version information available (required byore/pypy/bin/pypy: No module named pip", "stderr_lines": ["/home/core/pypy/bin/pypy: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/by: /lib64/libssl.so.1.0.0: no version information available (required by /home/core/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: /lib64/libcrypto.so.1.0.0: no versiocore/pypy/bin/libpypy-c.so)", "/home/core/pypy/bin/pypy: No module named pip"], "stdout": "", "stdout_lines": []}
...ignoring

TASK [defunctzombie.coreos-bootstrap : Copy get-pip.py] ********************************************************************************************************************
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]

TASK [defunctzombie.coreos-bootstrap : Install pip] ************************************************************************************************************************
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]

TASK [defunctzombie.coreos-bootstrap : Remove get-pip.py] ******************************************************************************************************************
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]

TASK [defunctzombie.coreos-bootstrap : Install pip launcher] ***************************************************************************************************************
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]
changed: [x.x.x.x]

PLAY RECAP *****************************************************************************************************************************************************************
x.x.x.x               : ok=7    changed=6    unreachable=0    failed=0   
x.x.x.x                : ok=7    changed=6    unreachable=0    failed=0   
x.x.x.x              : ok=7    changed=6    unreachable=0    failed=0   
x.x.x.x                : ok=7    changed=6    unreachable=0    failed=0   
x.x.x.x             : ok=7    changed=6    unreachable=0    failed=0   
x.x.x.x                : ok=7    changed=6    unreachable=0    failed=0   

core@host:~/cilium/installation/ansible$ ansible -i hosts mps,sps -m shell -a "free"
x.x.x.x | SUCCESS | rc=0 >>
             total       used       free     shared    buffers     cached
Mem:       8178284     414336    7763948        328      12288     202236
-/+ buffers/cache:     199812    7978472
Swap:            0          0          0

x.x.x.x | SUCCESS | rc=0 >>
             total       used       free     shared    buffers     cached
Mem:       8178280     412072    7766208        328      12308     202468
-/+ buffers/cache:     197296    7980984
Swap:            0          0          0

x.x.x.x | SUCCESS | rc=0 >>
             total       used       free     shared    buffers     cached
Mem:       3857388     559156    3298232        340      35180     316372
-/+ buffers/cache:     207604    3649784
Swap:            0          0          0

x.x.x.x | SUCCESS | rc=0 >>
             total       used       free     shared    buffers     cached
Mem:       3857388     557996    3299392        340      36384     316528
-/+ buffers/cache:     205084    3652304
Swap:            0          0          0

x.x.x.x | SUCCESS | rc=0 >>
             total       used       free     shared    buffers     cached
Mem:       3857388     559832    3297556        340      36412     317296
-/+ buffers/cache:     206124    3651264
Swap:            0          0          0

x.x.x.x | SUCCESS | rc=0 >>
             total       used       free     shared    buffers     cached
Mem:       8178284     411716    7766568        328      12320     201804
-/+ buffers/cache:     197592    7980692
Swap:            0          0          0
```

4.1 3.2 TLS Assets 
~~~~~~~~~~~~~~~~~~~~~~~~

```
core@host:~/cilium/installation/ansible$ 
$ ansible -i hosts mps -m shell -a "ls"
x.x.x.x | SUCCESS | rc=0 >>
apiserver-key.pem
apiserver.pem
bin
ca-key.pem
ca.pem
pypy

x.x.x.x | SUCCESS | rc=0 >>
apiserver-key.pem
apiserver.pem
bin
ca-key.pem
ca.pem
pypy

x.x.x.x | SUCCESS | rc=0 >>
apiserver-key.pem
apiserver.pem
bin
ca-key.pem
ca.pem
pypy
$ ansible -i hosts mps -b -m shell -a "mkdir -p /etc/kubernetes/ssl"
$ ansible -i hosts mps -b -m shell -a "mv apiserver-key.pem  apiserver.pem  ca-key.pem  ca.pem /etc/kubernetes/ssl/"
$ ansible -i hosts mps -b -m shell -a "ls "
x.x.x.x | SUCCESS | rc=0 >>
bin
pypy

x.x.x.x | SUCCESS | rc=0 >>
bin
pypy

x.x.x.x | SUCCESS | rc=0 >>
bin
pypy

$ ansible -i hosts mps -b -m shell -a "ls -lah /etc/kubernetes/ssl/*-key.pem"
x.x.x.x | SUCCESS | rc=0 >>
-rw-------. 1 root root 1.7K Jun 16 08:02 /etc/kubernetes/ssl/apiserver-key.pem
-rw-------. 1 root root 1.7K Jun 16 08:02 /etc/kubernetes/ssl/ca-key.pem

x.x.x.x | SUCCESS | rc=0 >>
-rw-------. 1 root root 1.7K Jun 16 08:03 /etc/kubernetes/ssl/apiserver-key.pem
-rw-------. 1 root root 1.7K Jun 16 08:03 /etc/kubernetes/ssl/ca-key.pem

x.x.x.x | SUCCESS | rc=0 >>
-rw-------. 1 root root 1.7K Jun 16 08:03 /etc/kubernetes/ssl/apiserver-key.pem
-rw-------. 1 root root 1.7K Jun 16 08:03 /etc/kubernetes/ssl/ca-key.pem
```


3.3 Start VMs if stopped
~~~~~~~~~~~~~~~~~~~~~~~~

::

```
core@host:~/cilium/installation/ansible$ for i in $M1 $M2 $M3; do aws ec2 start-instances --instance-ids $i; done;
core@host:~/cilium/installation/ansible$ for i in $M1 $M2 $M3; do aws ec2 describe-instance-status --instance-ids $i; done;
```
Re-check Public IPs
```
core@host:~/cilium/installation/ansible$ aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,PublicIpAddress,Tags[0].Value,ImageId,State.Name,Placement.AvailabilityZone,LaunchTime]' --filters Name=tag:Name,Values=cilium* --output text |sort -k 4|grep -v None
i-xxxxxxxxxxxxxxxxxxx	192.168.32.11	x.x.x.x	ciliumMaster1	ami-xxxxxxxx	running	us-west-1a	2017-06-29T08:43:00.000Z
i-xxxxxxxxxxxxxxxxxxx	192.168.32.12	x.x.x.x	ciliumMaster2	ami-xxxxxxxx	running	us-west-1a	2017-06-29T08:43:01.000Z
i-xxxxxxxxxxxxxxxxxxx	192.168.32.13	x.x.x.x	ciliumMaster3	ami-xxxxxxxx	running	us-west-1a	2017-06-29T08:43:03.000Z
```

3.4 Create and run ansible playbook 
~~~~~~~~~~~~~~~~~~~~~~~~

::

Create the roles/masters
https://quay.io/repository/coreos/hyperkube?tag=latest&tab=tags
```
core@host:~/cilium/installation/ansible$ /usr/bin/ansible --version
ansible 2.3.0.0
  config file = /etc/ansible/ansible.cfg
  configured module search path = Default w/o overrides
  python version = 2.7.6 (default, Oct 26 2016, 20:30:19) [GCC 4.8.4]
  
core@host:~/cilium/installation/ansible$ ansible -i hosts mp1 -b -m setup --tree /tmp/facts
```
```
core@host:~/cilium/installation/ansible/roles/masters/tasks$ vi main.yml 
- name: template_kubelet.service
  hosts: mps
  become: true
  remote_user: core
  handlers: 
    - include: ../handlers/main.yml
  tasks:

    - name: main.yml | Templating out kubelet.service script 
      template:
       src: ../templates/kubelet.service.j2
       dest: /etc/systemd/system/kubelet.service
       owner: root
       group: root
       mode: 0644
      notify: restart kubelet.service

    - name: main.yml | Creates directory /etc/kubernetes/manifests
      file: 
       path: /etc/kubernetes/manifests
       state: directory

    - name: main.yml | Creates directory /etc/cni/net.d
      file:
       path: /etc/cni/net.d
       state: directory

    - name: main.yml | Make sure kubelet.service is running and enabled
      systemd: name=kubelet.service state=started enabled=yes

    - name: main.yml | Templating out kube-apiserver.yaml pod script
      template:
       src: ../templates/kube-apiserver.yaml.j2
       dest: /etc/kubernetes/manifests/kube-apiserver.yaml
       owner: root
       group: root

    - name: main.yml | Templating out kube-controller-manager.yaml pod script
      template:
       src: ../templates/kube-controller-manager.yaml.j2
       dest: /etc/kubernetes/manifests/kube-controller-manager.yaml
       owner: root
       group: root

    - name: main.yml | Templating out kube-scheduler.yaml pod script
      template:
       src: ../templates/kube-scheduler.yaml.j2
       dest: /etc/kubernetes/manifests/kube-scheduler.yaml
       owner: root
       group: root

    - name: main.yml | Creates directory /opt/cni
      file:
       path: /opt/cni
       state: directory

    - name: main.yml | Download cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
      get_url:
       url: https://storage.googleapis.com/kubernetes-release/network-plugins/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
       dest: /home/core/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
       mode: 0440

    - name: main.yml | Extract cni archive
      unarchive:
       src: /home/core/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
       dest: /opt/cni
       remote_src: True
#       extra_opts: [--strip-components=1]

    - name: main.yml | Creates directory /opt/bin
      file:
       path: /opt/bin
       state: directory

    - name: main.yml | Download kubectl
      get_url:
       url: https://storage.googleapis.com/kubernetes-release/release/v1.6.6/bin/linux/amd64/kubectl
       dest: /opt/bin/kubectl
       mode: 0740

    - name: main.yml | Change the owner of kubectl to core
      file:
       path: /opt/bin/kubectl
       owner: core
       group: core
       mode: 0740

    - name: main.yml | Templating out cilium-ds.yaml script
      template:
       src: ../templates/cilium-ds.yaml.j2
       dest: /home/core/cilium-ds.yaml
       owner: root
       group: root
```
```
core@host:~/cilium/installation/ansible$ ansible-playbook -i hosts roles/masters/tasks/main.yml
core@host:~/cilium/installation/ansible$ ansible -i hosts mps -m shell -a "ls -lah /home/core"
core@host:~/cilium/installation/ansible$ ansible -i hosts mps -b -m shell -a "curl http://127.0.0.1:8080/version"
core@host:~/cilium/installation/ansible$ ansible -i hosts mps -b -m shell -a "ls -lah /opt/bin"
core@host:~/cilium/installation/ansible$ ansible -i host1 mps -b -m shell -a "kubectl get pods --namespace kube-system"
x.x.x.x | SUCCESS | rc=0 >>
NAME                                    READY     STATUS    RESTARTS   AGE
kube-apiserver-192.168.32.11            1/1       Running   2          11d
kube-apiserver-192.168.32.12            1/1       Running   1          11d
kube-apiserver-192.168.32.13            1/1       Running   1          11d
kube-controller-manager-192.168.32.11   1/1       Running   2          11d
kube-controller-manager-192.168.32.12   1/1       Running   1          11d
kube-controller-manager-192.168.32.13   1/1       Running   1          11d
kube-scheduler-192.168.32.11            1/1       Running   2          11d
kube-scheduler-192.168.32.12            1/1       Running   2          11d
kube-scheduler-192.168.32.13            1/1       Running   2          11d

x.x.x.x | SUCCESS | rc=0 >>
NAME                                    READY     STATUS    RESTARTS   AGE
kube-apiserver-192.168.32.11            1/1       Running   2          11d
kube-apiserver-192.168.32.12            1/1       Running   1          11d
kube-apiserver-192.168.32.13            1/1       Running   1          11d
kube-controller-manager-192.168.32.11   1/1       Running   2          11d
kube-controller-manager-192.168.32.12   1/1       Running   1          11d
kube-controller-manager-192.168.32.13   1/1       Running   1          11d
kube-scheduler-192.168.32.11            1/1       Running   2          11d
kube-scheduler-192.168.32.12            1/1       Running   2          11d
kube-scheduler-192.168.32.13            1/1       Running   2          11d

x.x.x.x | SUCCESS | rc=0 >>
NAME                                    READY     STATUS    RESTARTS   AGE
kube-apiserver-192.168.32.11            1/1       Running   2          11d
kube-apiserver-192.168.32.12            1/1       Running   1          11d
kube-apiserver-192.168.32.13            1/1       Running   1          11d
kube-controller-manager-192.168.32.11   1/1       Running   2          11d
kube-controller-manager-192.168.32.12   1/1       Running   1          11d
kube-controller-manager-192.168.32.13   1/1       Running   1          11d
kube-scheduler-192.168.32.11            1/1       Running   2          11d
kube-scheduler-192.168.32.12            1/1       Running   2          11d
kube-scheduler-192.168.32.13            1/1       Running   2          11d
core@host:~/cilium/installation/ansible$ ansible -i hosts mps -b -m shell -a "ls /home/core"
x.x.x.x | SUCCESS | rc=0 >>
bin
cilium-ds.yaml
cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
pypy

x.x.x.x | SUCCESS | rc=0 >>
bin
cilium-ds.yaml
cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
pypy

x.x.x.x | SUCCESS | rc=0 >>
bin
cilium-ds.yaml
cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
pypy


3.5 Create kube API load-balancer
~~~~~~~~~~~~~~~~~~~~~~~~

::

$ aws elb create-load-balancer --load-balancer-name "cilium-MasterHost-LB" --listeners Protocol="HTTP",LoadBalancerPort=8080,InstanceProtocol="HTTP",InstancePort=8080 --security-groups $SECURITY_GROUP_ID  --subnets $SUBNET_ID
{
    "DNSName": "cilium-MasterHost-LB-xxxxxxxxxxx.us-west-1.elb.amazonaws.com"
}

$ aws elb configure-health-check --load-balancer-name "cilium-MasterHost-LB" --health-check Target="HTTP:8080/healthz",Interval=30,Timeout=5,UnhealthyThreshold=2,HealthyThreshold=2
{
    "HealthCheck": {
        "HealthyThreshold": 2, 
        "Interval": 30, 
        "Target": "HTTP:8080/healthz", 
        "Timeout": 5, 
        "UnhealthyThreshold": 2
    }
}

$ aws elb register-instances-with-load-balancer --load-balancer-name "cilium-MasterHost-LB" --instances $M1 $M2 $M3
{
    "Instances": [
        {
            "InstanceId": "i-xxxxxxxxxxxxxxxxxxx"
        }, 
        {
            "InstanceId": "i-xxxxxxxxxxxxxxxxxxx"
        }, 
        {
            "InstanceId": "i-xxxxxxxxxxxxxxxxxxx"
        }
    ]
}
$ aws elb describe-instance-health --load-balancer-name "cilium-MasterHost-LB"
{
    "InstanceStates": [
        {
            "InstanceId": "i-xxxxxxxxxxxxxxxxxxx", 
            "ReasonCode": "N/A", 
            "State": "InService", 
            "Description": "N/A"
        }, 
        {
            "InstanceId": "i-xxxxxxxxxxxxxxxxxxx", 
            "ReasonCode": "N/A", 
            "State": "InService", 
            "Description": "N/A"
        }, 
        {
            "InstanceId": "i-xxxxxxxxxxxxxxxxxxx", 
            "ReasonCode": "N/A", 
            "State": "InService", 
            "Description": "N/A"
        }
    ]
}

$ vi create-resource-record-sets.json
----------------------
{
  "Comment": "to create api lb cname",
  "Changes": [
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "api.x.x.x.x",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "cilium-MasterHost-LB-xxxxxxxxxxx.us-west-1.elb.amazonaws.com"
          }
        ]
      }
    }
  ]
}
----------------------

$ aws route53 list-hosted-zones

$ aws route53 change-resource-record-sets --hosted-zone-id XXXXXXXXXXXXX --change-batch file://create-resource-record-sets.json

$ aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --protocol tcp --port 8080 --cidr 0.0.0.0/0

$ ansible -i hosts mps -b -m shell -a "curl http://cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com:8080/healthz"

$ ansible -i hosts mps -b -m shell -a "nslookup api.x.x.x.x"
x.x.x.x | SUCCESS | rc=0 >>
Server:		192.168.32.2
Address:	192.168.32.2#53

Non-authoritative answer:
api.x.x.x.x	canonical name = cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com.
Name:	cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com
Address: x.x.x.x
Name:	cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com
Address: x.x.x.x

x.x.x.x | SUCCESS | rc=0 >>
Server:		192.168.32.2
Address:	192.168.32.2#53

Non-authoritative answer:
api.x.x.x.x	canonical name = cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com.
Name:	cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com
Address: x.x.x.x
Name:	cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com
Address: x.x.x.x

x.x.x.x | SUCCESS | rc=0 >>
Server:		192.168.32.2
Address:	192.168.32.2#53

Non-authoritative answer:
api.x.x.x.x	canonical name = cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com.
Name:	cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com
Address: x.x.x.x
Name:	cilium-masterhost-lb-xxxxxxxxxxx.us-west-1.elb.amazonaws.com
Address: x.x.x.x

$ ansible -i hosts mp1 -b -m shell -a "curl http://api.x.x.x.x:8080/heathz"


x.x.x.x | SUCCESS | rc=0 >>
{
  "paths": [
    "/api",
    "/api/v1",
    "/apis",
    "/apis/apps",
    "/apis/apps/v1beta1",
    "/apis/authentication.k8s.io",
    "/apis/authentication.k8s.io/v1",
    "/apis/authentication.k8s.io/v1beta1",
    "/apis/authorization.k8s.io",
    "/apis/authorization.k8s.io/v1",
    "/apis/authorization.k8s.io/v1beta1",
    "/apis/autoscaling",
    "/apis/autoscaling/v1",
    "/apis/autoscaling/v2alpha1",
    "/apis/batch",
    "/apis/batch/v1",
    "/apis/batch/v2alpha1",
    "/apis/certificates.k8s.io",
    "/apis/certificates.k8s.io/v1beta1",
    "/apis/cilium.io",
    "/apis/cilium.io/v1",
    "/apis/extensions",
    "/apis/extensions/v1beta1",
    "/apis/policy",
    "/apis/policy/v1beta1",
    "/apis/rbac.authorization.k8s.io",
    "/apis/rbac.authorization.k8s.io/v1alpha1",
    "/apis/rbac.authorization.k8s.io/v1beta1",
    "/apis/settings.k8s.io",
    "/apis/settings.k8s.io/v1alpha1",
    "/apis/storage.k8s.io",
    "/apis/storage.k8s.io/v1",
    "/apis/storage.k8s.io/v1beta1",
    "/healthz",
    "/healthz/ping",
    "/healthz/poststarthook/bootstrap-controller",
    "/healthz/poststarthook/ca-registration",
    "/healthz/poststarthook/extensions/third-party-resources",
    "/logs",
    "/metrics",
    "/swaggerapi/",
    "/ui/",
    "/version"
  ]
}  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1285  100  1285    0     0  25185      0 --:--:-- --:--:-- --:--:--  313k
```

3.6 Set Up Cillium For Network Policy 
~~~~~~~~~~~~~~~~~~~~~~~~

::

core@host:~/cilium/installation/ansible$ ansible -i hosts mp1 -b -m shell -a "kubectl create -f cilium-ds.yaml"
x.x.x.x | SUCCESS | rc=0 >>
clusterrole "cilium" created
serviceaccount "cilium" created
clusterrolebinding "cilium" created
daemonset "cilium-consul" created
daemonset "cilium" created

core@host:~/cilium/installation/ansible$ ansible -i hosts mps -b -m shell -a "curl -s localhost:10255/pods | jq -r '.items[].metadata.name'"
 [WARNING]: Consider using get_url or uri module rather than running curl

x.x.x.x | SUCCESS | rc=0 >>
kube-apiserver-192.168.32.11
kube-controller-manager-192.168.32.11
kube-scheduler-192.168.32.11
cilium-consul-nrbgk
cilium-l0px6

x.x.x.x | SUCCESS | rc=0 >>
kube-apiserver-192.168.32.12
kube-controller-manager-192.168.32.12
kube-scheduler-192.168.32.12
cilium-consul-l3v28
cilium-248mn

x.x.x.x | SUCCESS | rc=0 >>
kube-scheduler-192.168.32.13
kube-apiserver-192.168.32.13
kube-controller-manager-192.168.32.13
cilium-consul-kb8t2
cilium-2lvdf

core@host:~/cilium/installation/ansible$ ansible -i hosts mp1 -b -m shell -a "kubectl get all --all-namespaces"
x.x.x.x | SUCCESS | rc=0 >>
NAMESPACE     NAME                                       READY     STATUS    RESTARTS   AGE
kube-system   po/cilium-1pt6z                            1/1       Running   7          14m
kube-system   po/cilium-consul-89bdb                     1/1       Running   0          14m
kube-system   po/cilium-consul-c98rp                     1/1       Running   0          14m
kube-system   po/cilium-consul-nlpgj                     1/1       Running   0          14m
kube-system   po/cilium-pp10n                            1/1       Running   7          14m
kube-system   po/cilium-xgh2f                            1/1       Running   6          14m
kube-system   po/kube-apiserver-192.168.32.11            1/1       Running   2          11d
kube-system   po/kube-apiserver-192.168.32.12            1/1       Running   1          11d
kube-system   po/kube-apiserver-192.168.32.13            1/1       Running   1          11d
kube-system   po/kube-controller-manager-192.168.32.11   1/1       Running   2          11d
kube-system   po/kube-controller-manager-192.168.32.12   1/1       Running   1          11d
kube-system   po/kube-controller-manager-192.168.32.13   1/1       Running   1          11d
kube-system   po/kube-scheduler-192.168.32.11            1/1       Running   2          11d
kube-system   po/kube-scheduler-192.168.32.12            1/1       Running   2          11d
kube-system   po/kube-scheduler-192.168.32.13            1/1       Running   2          11d
NAMESPACE   NAME             CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
default     svc/kubernetes   192.168.192.1   <none>        443/TCP   11d
```



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