.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_openshift_okd:

*****************************
Installation on OpenShift OKD
*****************************

OpenShift Requirements
======================

1. Choose preferred cloud provider. This guide was tested in AWS, Azure & GCP.

2. Read `OpenShift documentation <https://docs.okd.io/latest/welcome/index.html>`_ to find out about provider-specific prerequisites.

3. `Get OpenShift Installer <https://github.com/openshift/okd#getting-started>`_.

.. note::

   It's highly recommended to read the docs, unless you have installed
   OpenShift in the past. Here are a few notes that you may find useful.

   - with the AWS provider ``openshift-install`` will not work properly
     when MFA credentials are stored in ``~/.aws/credentials``, traditional credentials are required
   - with the Azure provider ``openshift-install`` will prompt for
     credentials and store them in ``~/.azure/osServicePrincipal.json``, it
     doesn't simply pickup ``az login`` credentials. It's recommended to
     setup a dedicated service principal and use it
   - with the GCP provider ``openshift-install`` will only work with a service
     account key, which has to be set using ``GOOGLE_CREDENTIALS``
     environment variable (e.g. ``GOOGLE_CREDENTIALS=service-account.json``).
     Follow `Openshift Installer documentation <https://github.com/openshift/installer/blob/master/docs/user/gcp/iam.md>`_
     to assign required roles to your service account.

Create an OpenShift OKD Cluster
===============================

First, set cluster name:

.. code:: bash

   CLUSTER_NAME="cluster-1"

Now, create configuration files:

.. note::

   The sample output below is showing the AWS provider, but
   it should work the same way with other providers.

.. code-block:: shell-session

   $ openshift-install create install-config --dir "${CLUSTER_NAME}"
   ? SSH Public Key ~/.ssh/id_rsa.pub
   ? Platform aws
   INFO Credentials loaded from default AWS environment variables
   ? Region eu-west-1
   ? Base Domain openshift-test-1.cilium.rocks
   ? Cluster Name cluster-1
   ? Pull Secret [? for help] **********************************

And set ``networkType: Cilium``:

.. code:: bash

   sed -i 's/networkType:\ OVNKubernetes/networkType:\ Cilium/' "${CLUSTER_NAME}/install-config.yaml"

Resulting configuration will look like this:

.. code:: yaml

   apiVersion: v1
   baseDomain: ilya-openshift-test-1.cilium.rocks
   compute:
   - architecture: amd64
     hyperthreading: Enabled
     name: worker
     platform: {}
     replicas: 3
   controlPlane:
     architecture: amd64
     hyperthreading: Enabled
     name: master
     platform: {}
     replicas: 3
   metadata:
     creationTimestamp: null
     name: cluster-1
   networking:
     clusterNetwork:
     - cidr: 10.128.0.0/14
       hostPrefix: 23
     machineNetwork:
     - cidr: 10.0.0.0/16
     networkType: Cilium
     serviceNetwork:
     - 172.30.0.0/16
   platform:
     aws:
       region: eu-west-1
   publish: External
   pullSecret: '{"auths":{"fake":{"auth": "bar"}}}'
   sshKey: |
     ssh-rsa <REDACTED>

You may wish to make a few changes, e.g. increase the number of nodes. If you do change any of the CIDRs,
you will need to make sure that Helm values used below reflect those changes. Namely - ``clusterNetwork``
should match ``clusterPoolIPv4PodCIDR`` & ``clusterPoolIPv4MaskSize``. Also make sure that the ``clusterNetwork``
does not conflict with ``machineNetwork`` (which represents the VPC CIDR in AWS).

Next, generate OpenShift manifests:

.. code:: bash

   openshift-install create manifests --dir "${CLUSTER_NAME}"

Now, define ``cilium`` namespace:

.. code:: bash

   cat << EOF > "${CLUSTER_NAME}/manifests/cluster-network-03-cilium-namespace.yaml"
   apiVersion: v1
   kind: Namespace
   metadata:
     name: cilium
     annotations:
       # node selector is required to make cilium-operator run on control plane nodes
       openshift.io/node-selector: ""
     labels:
       name: cilium
       # run level sets priority for Cilium to be deployed prior to other components
       openshift.io/run-level: "0"
       # enable cluster logging for Cilium namespace
       openshift.io/cluster-logging: "true"
       # enable cluster monitoring for Cilium namespace
       openshift.io/cluster-monitoring: "true"
   EOF

.. include:: k8s-install-download-release.rst

Next, render Cilium manifest:

.. parsed-literal::

   helm template |CHART_RELEASE|  \\
      --namespace cilium \\
      --set ipam.mode=cluster-pool \\
      --set cni.binPath=/var/lib/cni/bin \\
      --set cni.confPath=/var/run/multus/cni/net.d \\
      --set ipam.operator.clusterPoolIPv4PodCIDR=10.128.0.0/14 \\
      --set ipam.operator.clusterPoolIPv4MaskSize=23 \\
      --set nativeRoutingCIDR=10.128.0.0/14 \\
      --set bpf.masquerade=false \\
      --set endpointRoutes.enabled=true \\
      --output-dir "${OLDPWD}"
   cd "${OLDPWD}"

Copy Cilium manifest to ``${CLUSTER_NAME}/manifests``:

.. code:: bash

    for resource in cilium/templates/*
        do cp "${resource}" "${CLUSTER_NAME}/manifests/cluster-network-04-cilium-$(basename ${resource})"
    done

Create the cluster:

.. note::

   The sample output below is showing the AWS provider, but
   it should work the same way with other providers.

.. code-block:: shell-session

   $ openshift-install create cluster --dir "${CLUSTER_NAME}"
   WARNING   Discarding the Bootstrap Ignition Config that was provided in the target directory because its dependencies are dirty and it needs to be regenerated
   INFO Consuming OpenShift Install (Manifests) from target directory
   INFO Consuming Master Machines from target directory
   INFO Consuming Worker Machines from target directory
   INFO Consuming Bootstrap Ignition Config from target directory
   INFO Consuming Common Manifests from target directory
   INFO Consuming Openshift Manifests from target directory
   INFO Credentials loaded from default AWS environment variables
   INFO Creating infrastructure resources...
   INFO Waiting up to 20m0s for the Kubernetes API at https://api.cluster-1.openshift-test-1.cilium.rocks:6443...
   INFO API v1.18.3 up
   INFO Waiting up to 40m0s for bootstrapping to complete...

Next, firewall configuration must be updated to allow `Cilium
ports <https://docs.cilium.io/en/v1.8/install/system_requirements/#firewall-rules>`_.
Please note that ``openshift-install`` doesn't support custom firewall
rules, so you will need to use one of the following scripts if you are
using AWS or GCP. Azure does not need additional configuration.

.. warning::

   **You need to execute the following command to configure firewall rules just after**
   ``INFO Waiting up to 40m0s for bootstrapping to complete...`` **appears in the logs,
   or the installation will fail**. It is safe to apply these changes once, OpenShift will
   not override these.

.. tabs::

   .. tab:: AWS: enable Cilium ports

      This script depends on ``jq`` & AWS CLI (``aws``). Make sure to run
      it inside of the same working directory where ``${CLUSTER_NAME}``
      directory is present.

      .. code:: bash

         infraID="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.infraID')"
         aws_region="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.aws.region')"
         cluster_tag="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.aws.identifier[0] | to_entries | "Name=tag:\(.[0].key),Values=\(.[0].value)"')"

         worker_sg="$(aws ec2 describe-security-groups --region "${aws_region}" --filters "${cluster_tag}" "Name=tag:Name,Values=${infraID}-worker-sg" | jq -r '.SecurityGroups[0].GroupId')"
         master_sg="$(aws ec2 describe-security-groups --region "${aws_region}" --filters "${cluster_tag}" "Name=tag:Name,Values=${infraID}-master-sg" | jq -r '.SecurityGroups[0].GroupId')"

         aws ec2 authorize-security-group-ingress --region "${aws_region}" \
            --ip-permissions \
               "IpProtocol=udp,FromPort=8472,ToPort=8472,UserIdGroupPairs=[{GroupId=${worker_sg}},{GroupId=${master_sg}}]" \
               "IpProtocol=tcp,FromPort=4240,ToPort=4240,UserIdGroupPairs=[{GroupId=${worker_sg}},{GroupId=${master_sg}}]" \
            --group-id "${worker_sg}"

         aws ec2 authorize-security-group-ingress --region "${aws_region}" \
            --ip-permissions \
               "IpProtocol=udp,FromPort=8472,ToPort=8472,UserIdGroupPairs=[{GroupId=${worker_sg}},{GroupId=${master_sg}}]" \
               "IpProtocol=tcp,FromPort=4240,ToPort=4240,UserIdGroupPairs=[{GroupId=${worker_sg}},{GroupId=${master_sg}}]" \
            --group-id "${master_sg}"

   .. tab:: GCP: enable Cilium ports

      This script depends on ``jq`` & Google Cloud SDK (``gcloud``). Make sure
      to run it inside of the same working directory where ``${CLUSTER_NAME}``
      directory is present.

      .. code:: bash

         infraID="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.infraID')"
         gcp_projectID="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.gcp.projectID')"

         gcloud compute firewall-rules create \
            --project="${gcp_projectID}" \
            --network="${infraID}-network" \
            --allow=tcp:4240,udp:8472,icmp \
            --source-tags="${infraID}-worker,${infraID}-master" \
            --target-tags="${infraID}-worker,${infraID}-master" \
              "${infraID}-cilium"

Accessing the cluster
---------------------

To access the cluster you will need to use ``kubeconfig`` file from the ``${CLUSTER_NAME}/auth`` directory:

.. code:: bash

   export KUBECONFIG="${CLUSTER_NAME}/auth/kubeconfig"

Prepare cluster for Cilium connectivity test
--------------------------------------------

In order for Cilium connectivity test pods to run on OpenShift, a simple custom ``SecurityContextConstraints``
object is required. It will to allow ``hostPort``/``hostNetwork`` that some of the connectivity test pods rely on,
it sets only ``allowHostPorts`` and ``allowHostNetwork`` without any other privileges.

.. code:: bash

   kubectl apply -f - << EOF
   apiVersion: security.openshift.io/v1
   kind: SecurityContextConstraints
   metadata:
     name: cilium-test
   allowHostPorts: true
   allowHostNetwork: true
   users:
     - system:serviceaccount:cilium-test:default
   priority: null
   readOnlyRootFilesystem: false
   runAsUser:
     type: MustRunAsRange
   seLinuxContext:
     type: MustRunAs
   volumes: null
   allowHostDirVolumePlugin: false
   allowHostIPC: false
   allowHostPID: false
   allowPrivilegeEscalation: false
   allowPrivilegedContainer: false
   allowedCapabilities: null
   defaultAddCapabilities: null
   requiredDropCapabilities: null
   groups: null
   EOF

.. include:: k8s-install-connectivity-test.rst

Cleanup after connectivity test
-------------------------------

Remove ``cilium-test`` namespace:

.. code:: bash

   kubectl delete ns cilium-test

Remove ``SecurityContextConstraints``:

.. code:: bash

   kubectl delete scc cilium-test
