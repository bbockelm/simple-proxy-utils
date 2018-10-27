Simple Proxy Utilities
======================

This repository contains a few helper functions for verifying and extracting
information from PEM-formatted proxy chains.

The resulting libSimpleProxyUtils.so module utilizes the underlying Globus
and VOMS C libraries to do the extraction and aims to provide a simplified,
thread-safe interface.

Python Interface
----------------

This library includes a python module that exports a light wrapper around the
C library.  This includes a single public function, `chain_verify`, that both
verifies the proxy chain and returns the relevant identity (DN) and VOMS FQANs

Example usage:

```
def main():
    # Try to locate the proxy file from the runtime environment
    x509_loc = os.environ.get('X509_USER_PROXY')
    if not x509_loc:
        x509_loc = "/tmp/x509up_u" + str(os.geteuid())

    with open(x509_loc, "r") as fp:
        contents = fp.read()

    # Parse, verify, and extract the identity information.
    dn, fqans = simple_proxy_utils.chain_verify(contents)
    print "Identity: ", dn
    if fqans:
        print "FQANs:"
        for fqan in fqans:
            print "-", fqan
```
