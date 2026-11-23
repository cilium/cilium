.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


TLS Options
*****************************

TLS options enable extended TLS configuration per listener(``spec.listeners[].tls.options``)
via key/value pairs. Cilium does not support TLS options on TLS passthrough listeners and 
such a listener will be rejected. Cilium supports the following TLS options:

- ``cilium.io/tls-min-version`` -- minimum TLS version.
- ``cilium.io/tls-max-version`` -- maximum TLS version.
- ``cilium.io/tls-cipher-suites`` -- comma-separated list of cipher suites.
- ``cilium.io/tls-ecdh-curves`` -- comma-separated list of ECDH curves or key exchange algorithms.
- ``cilium.io/tls-signature-algorithms`` -- comma-separated list of signature-algorithms.

Both ``cilium.io/tls-min-version`` and ``cilium.io/tls-max-version`` can be either of two values,
``1.2`` or ``1.3``. If not set, they get default values ``1.2`` or ``1.3`` respectively. Cilium
rejects configurations where the minimum TLS version exceeds the maximum.

The following values can be assigned to ``cilium.io/tls-cipher-suites`` option.
These cipher suites apply to TLS ``1.2``, this option has no effect for TLS ``1.3``.

- ``AES128-GCM-SHA256``
- ``AES128-SHA``
- ``AES256-GCM-SHA384``
- ``AES256-SHA``
- ``ECDHE-ECDSA-AES128-GCM-SHA256``
- ``ECDHE-ECDSA-AES128-SHA``
- ``ECDHE-ECDSA-AES256-GCM-SHA384``
- ``ECDHE-ECDSA-AES256-SHA``
- ``ECDHE-ECDSA-CHACHA20-POLY1305``
- ``ECDHE-RSA-AES128-GCM-SHA256``
- ``ECDHE-RSA-AES128-SHA``
- ``ECDHE-RSA-AES256-GCM-SHA384``
- ``ECDHE-RSA-AES256-SHA``
- ``ECDHE-RSA-CHACHA20-POLY1305``
- ``DES-CBC3-SHA``
- ``ECDHE-ECDSA-AES128-SHA256``
- ``ECDHE-RSA-AES128-SHA256``

The following values can be assigned to ``cilium.io/tls-ecdh-curves`` option.

- ``MLKEM1024``
- ``P-256``
- ``P-384``
- ``P-521``
- ``X25519``
- ``X25519MLKEM768``

The following values can be assigned to ``cilium.io/tls-signature-algorithms`` option.

- ``ecdsa_secp256r1_sha256``
- ``ecdsa_secp384r1_sha384``
- ``ecdsa_secp521r1_sha512``
- ``ecdsa_sha1``
- ``ed25519``
- ``rsa_pkcs1_sha1``
- ``rsa_pkcs1_sha256``
- ``rsa_pkcs1_sha384``
- ``rsa_pkcs1_sha512``
- ``rsa_pss_rsae_sha256``
- ``rsa_pss_rsae_sha384``
- ``rsa_pss_rsae_sha512``
- ``mldsa44`` -- valid only for TLS ``1.3``.
- ``mldsa65`` -- valid only for TLS ``1.3``.
- ``mldsa87`` -- valid only for TLS ``1.3``.
- ``rsa_pkcs1_sha256_legacy`` -- valid only for TLS ``1.3`` client-certificate signatures.
