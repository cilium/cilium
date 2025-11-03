.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_lvh_tests:

####################################
Run eBPF Tests with Little VM Helper
####################################

Prerequisites
-------------

- Install ``qemu-utils``:

  .. code-block:: shell-session

      $ sudo apt-get install qemu-utils

Build Little VM Helper CLI
--------------------------

- Checkout the LVH repo:

  .. code-block:: shell-session

      $ gh repo clone cilium/little-vm-helper

- Build the CLI:

  .. code-block:: shell-session

      $ make little-vm-helper

VM image selection and preparation
----------------------------------

- You can find all available image types `here <https://quay.io/organization/lvh-images>`_. In this tutorial we use the ``complexity-test`` image.

- Pull the image:

  .. code-block:: shell-session

      $ ./lvh images pull quay.io/lvh-images/complexity-test:bpf-net-main --dir /var/tmp/

- Resize the image (optional):

  .. code-block:: shell-session

      $ qemu-img resize /var/tmp/images/complexity-test_bpf-net.qcow2 +16G

VM preparation
--------------

- Run the VM:

  .. code-block:: shell-session

      $ ./lvh run --image /var/tmp/images/complexity-test_bpf-net.qcow2 \
            --host-mount <path-to-cilium-repo> \
            --cpu-kind=host \
            --cpu=2 \
            --mem=8G \
            -p 2222:22 \
            --console-log-file=/tmp/lvh-console.log

- SSH to the VM:

  .. code-block:: shell-session

      $ ssh -p 2222 root@localhost
      $ resize2fs /dev/vda
      $ git config --global --add safe.directory /host
      $ apt update && apt install -y -o Dpkg::Options::="--force-confold" xxd docker-buildx-plugin

Run tests
---------

- All tests:

  .. code-block:: shell-session

      $ cd /host
      $ make run_bpf_tests

- Specific test:

  .. code-block:: shell-session

      $ cd /host
      $ make run_bpf_tests BPF_TEST="xdp_nodeport_lb4_nat_lb"

- Verbose mode:

  .. code-block:: shell-session

      $ cd /host
      $ make run_bpf_tests BPF_TEST_VERBOSE=1

- Dump context:

  .. code-block:: shell-session

      $ cd /host
      $ make run_bpf_tests BPF_TEST_DUMP_CTX=1 BPF_TEST_VERBOSE=1
