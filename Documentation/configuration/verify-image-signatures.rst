.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _verify_image_signatures:

**************************
Verifying Image Signatures
**************************

Prerequisites
=============

You will need to `install cosign`_.

.. _`install cosign`: https://docs.sigstore.dev/cosign/installation/

Verify Signed Container Images
==============================

For a complete list of images that are signed, please refer to `Releases`_.

Let's pick one image from this list and verify its signature using the ``cosign verify`` command:

.. code-block:: shell-session

    $ COSIGN_EXPERIMENTAL=1 cosign verify quay.io/cilium/cilium:v1.x.x

.. note::
    ``COSIGN_EXPERIMENTAL=1`` is used to allow verification of images signed in 
    ``KEYLESS`` mode. To learn more about keyless signing, please refer to `Keyless Signatures`_.

.. _`Releases`: https://github.com/cilium/cilium/releases
.. _`Keyless Signatures`: https://github.com/sigstore/cosign/blob/main/KEYLESS.md#keyless-signatures
