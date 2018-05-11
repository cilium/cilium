**********************************
Kubernetes Kops Installation Guide
**********************************

As of `kops<https://github.com/kubernetes/kops>`_ 1.9 release, Cilium is a supported CNI plugin for kops-deployed clusters.

Cilium needs a newer kernel version than the default kops images provide (minimum kernel version for Cilium is 4.8), so you need to supply an `ami<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html>`_ which will be new enough for Cilium to run on it.

CoreOS images have new enough kernels for Cilium to run on them and are tested by kops developers, which makes them a perfect candidate.

The latest stable CoreOS AMI can be found using aws cli:

.. code:: bash

    $ aws ec2 describe-images --region=us-east-1 --owner=595879546273 \
        --filters "Name=virtualization-type,Values=hvm" "Name=name,Values=CoreOS-stable*" \
        --query 'sort_by(Images,&CreationDate)[-1].{id:ImageLocation}'

    {
        "id": "595879546273/CoreOS-stable-1576.4.0-hvm"
    }

You also need to change the default etcd version used in kops, as Cilium needs at least version 3.1 (kops default is still on 2.0 branch).

The following is an example command for creating a Cilium-backed kops cluster:

.. code:: bash

    $ export KOPS_FEATURE_FLAGS=SpecOverrideFlag #for etcd override
    $ kops create cluster \
    --zones <zones, e.g. "eu-central-1a"> \
    --image 595879546273/CoreOS-stable-1576.4.0-hvm \ #check the command above to verify this is the newest CoreOS image
    --networking cilium \
    --override "cluster.spec.etcdClusters[*].version=3.1.11" \
    --kubernetes-version <e.g. "1.8.7">
