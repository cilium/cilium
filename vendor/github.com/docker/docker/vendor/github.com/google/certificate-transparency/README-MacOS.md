OS X Specific Instructions
==========================

Builds
------

We recommend that you use GClient to build on OSX. Please follow the
instructions in the [main readme](README.md) file.

Trusted root certificates
-------------------------

The CT code requires a set of trusted root certificates in order to:
   1. Validate outbound HTTPS connections
   2. (In the case of the log-server) decide whether to accept a certificate
      chain for inclusion.

On OSX, the system version of OpenSSL (0.9.8gz at time of writing) contains
Apple-provided patches which intercept failed chain validations and re-attempts
them using roots obtained from the system keychain. Since we use a much more
recent (and unpatched) version of OpenSSL this behaviour is unsupported and so
a PEM file containing the trusted root certs must be used.

To use a certificate PEM bundle file with the CT C++ code, the following
methods may be used.

### Incoming inclusion requests (ct-server only)

Set the `--trusted_cert_file` flag to point to the location of the PEM file
containing the set of root certificates whose chains should be accepted for
inclusion into the log.

### For verifying outbound HTTPS connections (ct-mirror)

Either set the `--trusted_roots_certs` flag, or the `SSL_CERT_FILE`
environment variable, to point to the location of the PEM file containing the
root certificates to be used to verify the outbound HTTPS connection.

Sources of trusted roots
------------------------

Obviously the choice of root certificates to trust for outbound HTTPS
connections and incoming inclusion requests are a matter of operating policy,
but it is often useful to have a set of common roots for testing and
development at the very least.

While OSX ships with a set of common trusted roots, they are not directly
available to OpenSSL and must be exported from the keychain first.  This can be
achieved with the following command:

```bash
security find-certificates -a -p /Library/Keychains/System.keychain > certs.pem
security find-certificates -a -p /System/Library/Keychains/SystemRootCertificates.keychain >> certs.pem
```

