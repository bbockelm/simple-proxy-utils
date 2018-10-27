#!/usr/bin/python

import os
import ctypes
import threading

__lib_handle = None
__lib_handle_lock = threading.Lock()
def __get_lib():
    """
    Returns a reference to the appropriate simple proxy utils library.
    """
    global __lib_handle
    with __lib_handle_lock:
        if __lib_handle == None:
            __lib_handle = ctypes.cdll.LoadLibrary("libSimpleProxyUtils.so")
        return __lib_handle


class ProxyVerifyException(Exception):
    pass


def chain_verify(cert_pem):
    """
    Given the text representation of a cert chain, verify it is valid
    and return the corresponding DN and FQAN list.

    Throws an exception if verification fails.

    Returns (dn, fqan_list), where fqan_list may be empty.
    """
    lib = __get_lib()
    chain_verify = lib.chain_verify
    chain_verify.restype = ctypes.c_int
    err_msg = ctypes.c_char_p()
    ident = ctypes.c_char_p()
    fqans_ptr = ctypes.POINTER(ctypes.c_char_p)()
    fqans_count = ctypes.c_int()
    retval = lib.chain_verify(cert_pem, ctypes.byref(ident), ctypes.byref(fqans_ptr), ctypes.byref(fqans_count), ctypes.byref(err_msg))
    fqans = []
    for idx in range(fqans_count.value):
        fqans.append(fqans_ptr[idx])
    if not retval:
        lib.fqans_free(fqans_ptr)
    else:
        raise ProxyVerifyException(err_msg.value)
    return ident.value, fqans

def main():
    x509_loc = os.environ.get('X509_USER_PROXY')
    if not x509_loc:
        x509_loc = "/tmp/x509up_u" + str(os.geteuid())

    with open(x509_loc, "r") as fp:
        contents = fp.read()

    dn, fqans = chain_verify(contents)
    print "Identity: ", dn
    if fqans:
        print "FQANs:"
        for fqan in fqans:
            print "-", fqan

if __name__ == '__main__':
    main()

