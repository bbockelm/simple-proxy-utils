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
    retval = lib.chain_verify(cert_pem, ident, None, ctypes.byref(err_msg))
    print retval, err_msg.value


def main():
    x509_loc = os.environ.get('X509_USER_PROXY')
    if not x509_loc:
        x509_loc = "/tmp/x509up_u" + str(os.geteuid())

    with open(x509_loc, "r") as fp:
        contents = fp.read()

    print chain_verify(contents)

if __name__ == '__main__':
    main()

