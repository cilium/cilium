.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _sbom:

**************************
Software Bill of Materials
**************************

A Software Bill of Materials (SBOM) is a complete, formally structured list of
components that are required to build a given piece of software. SBOM provides
insight into the software supply chain and any potential concerns related to
license compliance and security that might exist.

The Cilium SBOM is generated using the `syft`_ tool. To learn more about SBOM, see
`what an SBOM can do for you`_.

.. _`syft`: https://github.com/anchore/syft
.. _`what an SBOM can do for you`: https://www.chainguard.dev/unchained/what-an-sbom-can-do-for-you

Prerequisites
=============

- `Install cosign`_

.. _`Install cosign`: https://docs.sigstore.dev/cosign/installation/

Download SBOM
=============

You can download the SBOM in-toto attestation from the supplied Cilium image using the following command:

.. code-block:: shell-session

    $ cosign download attestation --predicate-type spdxjson <Image URI> | jq -r .payload | base64 -d | jq .predicate > ciliumSBOM.spdx.json

Verify SBOM attestation
=======================

To verify the SBOM in-toto attestation on the supplied Cilium image, run the following command:

.. parsed-literal::
    
    $ TAG = |IMAGE_TAG|
    $ cosign verify-attestation --certificate-github-workflow-repository cilium/cilium \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp https://github.com/cilium/cilium/.github/workflows \
    --type spdxjson <Image URI> | 2>&1   | head -n 13

For example:

.. code-block:: shell-session

    $ cosign verify-attestation --certificate-github-workflow-repository cilium/cilium \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp https://github.com/cilium/cilium/.github/workflows \
    --type spdxjson quay.io/cilium/cilium-ci:e5495c548abd25b6672431c02bb6c0460925baff  2>&1 | head -n 13

    Verification for quay.io/cilium/cilium-ci:e5495c548abd25b6672431c02bb6c0460925baff --
    The following checks were performed on each of these signatures:
      - The cosign claims were validated
      - Existence of the claims in the transparency log was verified offline
      - The code-signing certificate was verified using trusted certificate authority certificates
    Certificate subject: https://github.com/cilium/cilium/.github/workflows/build-images-ci.yaml@refs/pull/31028/merge
    Certificate issuer URL: https://token.actions.githubusercontent.com
    GitHub Workflow Trigger: pull_request
    GitHub Workflow SHA: 89175f13a4a0d6b79e06902e3e6a6ab55358001a
    GitHub Workflow Name: Image CI Build
    GitHub Workflow Repository: cilium/cilium
    GitHub Workflow Ref: refs/pull/31028/merge
    
It can be validated that the image was signed using Github Actions in the Cilium repository from the ``GitHub Workflow Repository``, ``Certificate subject`` and ``Certificate issuer URL`` fields of the output.

.. note::
    The `in-toto`_ Attestation Framework provides a specification for generating
    verifiable claims about any aspect of how a piece of software is produced.
    Consumers or users of software can then validate the origins of the software,
    and establish trust in its supply chain, using in-toto attestations.

.. _`in-toto`: https://in-toto.io/
