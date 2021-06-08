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

1. Choose preferred cloud provider. This guide was tested in AWS, Azure, and GCP
   from a Linux host.

2. Read `OpenShift documentation <https://docs.okd.io/latest/welcome/index.html>`_ to find out about provider-specific prerequisites.

3. `Get OpenShift Installer <https://github.com/openshift/okd#getting-started>`_.

.. note::

   It is highly recommended to read the OpenShift documentation, unless you have
   installed OpenShift in the past. Here are a few notes that you may find
   useful.

   - With the AWS provider ``openshift-install`` will not work properly
     when MFA credentials are stored in ``~/.aws/credentials``, traditional credentials are required.
   - With the Azure provider ``openshift-install`` will prompt for
     credentials and store them in ``~/.azure/osServicePrincipal.json``, it
     doesn't simply pickup ``az login`` credentials. It's recommended to
     setup a dedicated service principal and use it.
   - With the GCP provider ``openshift-install`` will only work with a service
     account key, which has to be set using ``GOOGLE_CREDENTIALS``
     environment variable (e.g. ``GOOGLE_CREDENTIALS=service-account.json``).
     Follow `Openshift Installer documentation <https://github.com/openshift/installer/blob/master/docs/user/gcp/iam.md>`_
     to assign required roles to your service account.

Create an OpenShift OKD Cluster
===============================

First, set the cluster name:

.. code-block:: shell-session

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

.. code-block:: shell-session

   sed -i "s/networkType: .*/networkType: Cilium/" "${CLUSTER_NAME}/install-config.yaml"

The resulting configuration will look like this:

.. code-block:: yaml

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

You may wish to make a few changes, e.g. increase the number of nodes.

If you do change any of the CIDRs, you will need to make sure that Helm values in ``${CLUSTER_NAME}/manifests/cluster-network-07-cilium-ciliumconfig.yaml``
reflect those changes. Namely ``clusterNetwork`` should match ``nativeRoutingCIDR``, ``clusterPoolIPv4PodCIDR`` and ``clusterPoolIPv4MaskSize``.
Also make sure that the ``clusterNetwork`` does not conflict with ``machineNetwork`` (which represents the VPC CIDR in AWS).

.. warning::

   Ensure that there are multiple replicas of the ``controlPlane``. A single
   ``controlPlane`` will lead to failure to bootstrap the cluster during
   installation.

Next, generate OpenShift manifests:

.. code-block:: shell-session

   openshift-install create manifests --dir "${CLUSTER_NAME}"

Next, obtain Cilium manifest from ``cilium/cilium-olm`` repository and copy to ``${CLUSTER_NAME}/manifests``:

.. code-block:: shell-session

   cilium_olm_rev="master"
   cilium_version="\ |release|\ "

   curl --silent --location --fail --show-error "https://github.com/cilium/cilium-olm/archive/${cilium_olm_rev}.tar.gz" --output /tmp/cilium-olm.tgz
   tar -C /tmp -xf /tmp/cilium-olm.tgz

   cp /tmp/cilium-olm-${cilium_olm_rev}/manifests/cilium.v${cilium_version}/* "${CLUSTER_NAME}/manifests"

   rm -rf -- /tmp/cilium-olm.tgz "/tmp/cilium-olm-${cilium_olm_rev}"

At this stage manifest directory contains all that is needed to install Cilium.
To get a list of the Cilium manifests, run:

.. code-block:: shell-session

   ls ${CLUSTER_NAME}/manifests/cluster-network-*-cilium-*

You can set any custom Helm values by editing ``${CLUSTER_NAME}/manifests/cluster-network-07-cilium-ciliumconfig.yaml``.

It is also possible to update Helm values once the cluster is running by
changing the ``CiliumConfig`` object, e.g. with ``kubectl edit ciliumconfig -n
cilium cilium``. You may need to restart the Cilium agent pods for certain
options to take effect.

.. note::

   If you are not using a real OpenShift pull secret, you will not be able to install the Cilium OLM operator
   using RedHat registry. You can fix this by running:

   .. code-block:: shell-session

       sed -i 's|image:\ registry.connect.redhat.com/isovalent/|image:\ quay.io/cilium/|g' \
         "${CLUSTER_NAME}/manifests/cluster-network-06-cilium-00002-cilium-olm-deployment.yaml" \
         ${CLUSTER_NAME}/manifests/cluster-network-06-cilium-00014-cilium.*-clusterserviceversion.yaml


Create the cluster:

.. note::

   The sample output below is showing the AWS provider, but
   it should work the same way with other providers.

.. code-block:: shell-session

   $ openshift-install create cluster --dir "${CLUSTER_NAME}"
   INFO Consuming OpenShift Install (Manifests) from target directory
   INFO Consuming Master Machines from target directory
   INFO Consuming Worker Machines from target directory
   INFO Consuming Openshift Manifests from target directory
   INFO Consuming Common Manifests from target directory
   INFO Credentials loaded from the "default" profile in file "/home/twp/.aws/credentials"
   INFO Creating infrastructure resources...
   INFO Waiting up to 20m0s for the Kubernetes API at https://api.cluster-name.ilya-openshift-test-1.cilium.rocks:6443...
   INFO API v1.20.0-1058+7d0a2b269a2741-dirty up
   INFO Waiting up to 30m0s for bootstrapping to complete...
   INFO Destroying the bootstrap resources...
   INFO Waiting up to 40m0s for the cluster at https://api.cluster-name.ilya-openshift-test-1.cilium.rocks:6443 to initialize...
   INFO Waiting up to 10m0s for the openshift-console route to be created...
   INFO Install complete!
   INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/home/twp/okd/cluster-name/auth/kubeconfig'
   INFO Access the OpenShift web-console here: https://console-openshift-console.apps.cluster-name.ilya-openshift-test-1.cilium.rocks
   INFO Login to the console with user: "kubeadmin", and password: "<REDACTED>"
   INFO Time elapsed: 32m9s

Next, the firewall configuration must be updated to allow Cilium ports :ref:`firewall_requirements`.
``openshift-install`` does not support custom firewall rules, so you will need to
use one of the following scripts if you are using AWS or GCP. Azure does not
need additional configuration.

.. warning::

   **You need to execute the following command to configure firewall rules just after**
   ``INFO Waiting up to 40m0s for bootstrapping to complete...`` **appears in the logs,
   or the installation will fail**. It is safe to apply these changes once, OpenShift will
   not override these.

.. tabs::

   .. tab:: AWS: enable Cilium ports

      This script depends on ``jq`` and the AWS CLI (``aws``). Make sure to run
      it inside of the same working directory where ``${CLUSTER_NAME}``
      directory is present.

      .. code-block:: shell-session

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

      This script depends on ``jq`` and the Google Cloud SDK (``gcloud``). Make
      sure to run it inside of the same working directory where
      ``${CLUSTER_NAME}`` directory is present.

      .. code-block:: shell-session

         infraID="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.infraID')"
         gcp_projectID="$(jq -r < "${CLUSTER_NAME}/metadata.json" '.gcp.projectID')"

         gcloud compute firewall-rules create \
            --project="${gcp_projectID}" \
            --network="${infraID}-network" \
            --allow=tcp:4240,udp:8472,icmp \
            --source-tags="${infraID}-worker,${infraID}-master" \
            --target-tags="${infraID}-worker,${infraID}-master" \
              "${infraID}-cilium"

   .. tab:: Azure: enable Cilium ports

      No additional configuration is needed.

Accessing the cluster
---------------------

To access the cluster you will need to use ``kubeconfig`` file from the ``${CLUSTER_NAME}/auth`` directory:

.. code-block:: shell-session

   export KUBECONFIG="${CLUSTER_NAME}/auth/kubeconfig"

Prepare cluster for Cilium connectivity test
--------------------------------------------

In order for Cilium connectivity test pods to run on OpenShift, a simple custom ``SecurityContextConstraints``
object is required. It will to allow ``hostPort``/``hostNetwork`` that some of the connectivity test pods rely on,
it sets only ``allowHostPorts`` and ``allowHostNetwork`` without any other privileges.

.. code-block:: shell-session

   kubectl apply -f - <<EOF
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

Deploy the connectivity test
----------------------------

.. include:: kubectl-connectivity-test.rst

Cleanup after connectivity test
-------------------------------

Remove the ``SecurityContextConstraints``:

.. code-block:: shell-session

   kubectl delete scc cilium-test

Delete the cluster
------------------

.. code-block:: shell-session

   openshift-install destroy cluster --dir="${CLUSTER_NAME}"
