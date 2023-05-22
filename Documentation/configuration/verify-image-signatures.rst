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

Since version 1.13, all Cilium container images are signed using cosign.

Let's verify a Cilium image's signature using the ``cosign verify`` command:

.. code-block:: shell-session

    $ TAG=v1.13.0
    $ cosign verify --certificate-github-workflow-repository cilium/cilium \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-name "Image Release Build" \
    --certificate-github-workflow-ref refs/tags/${TAG} \
    --certificate-identity "https://github.com/cilium/cilium/.github/workflows/build-images-releases.yaml@refs/tags/${TAG}" \
    "quay.io/cilium/cilium:${TAG}" | jq
    

.. note::

    ``cosign`` is used to verify images signed in ``KEYLESS`` mode. To learn
    more about keyless signing, please refer to `Keyless Signatures`_.
    
    ``--certificate-github-workflow-name string`` contains the workflow claim 
    from the GitHub OIDC Identity token that contains the name of the executed 
    workflow. For the names of workflows used to build Cilium images, see the 
    ``build-images`` workflows under `Cilium workflows`_.
    
    ``--certificate-github-workflow-ref string`` contains the ref claim from 
    the GitHub OIDC Identity token that contains the git ref that the workflow 
    run was based upon.

    ``--certificate-identity`` is used to verify the identity of the certificate
    from the Github build images release workflow.
    

.. _`Keyless Signatures`: https://docs.sigstore.dev/cosign/keyless/
.. _`Cilium workflows`: https://github.com/cilium/cilium/tree/main/.github/workflows
