
#ifndef __GLOBUS_SUPPORT_H_
#define __GLOBUS_SUPPORT_H_

/**
 * Activate the globus modules.  Returns true on success and false otherwise.
 */
bool globus_activate();

/**
 * Deactivate the globus modules.  Returns true on success and false otherwise.
 */
bool globus_deactivate();

/**Validate a x509 chain using the globus libraries.
 * - `cert` is the client certificate used to authenticate the
 *   TLS connection.
 * - `chain` is the remainder of the chain.
 * - `dn` is the output variable; it is the traditional Globus representation
 *   of the DN.  Only filled in if globus_verify returns true.
 * - `err_msg`, if non-null, will be contain an error message on failure.
 * - Returns true on success and false otherwise.
 *
 *  The caller is responsible for invoking `free` on the memory allocated to
 *  output variables.
 */
bool globus_verify(X509* cert, STACK_OF(X509*) chain, char **dn, char **err_msg);

/**
 * Uses Globus to create a cert and chain from a PEM-formatted string in memory.
 * - `creds`: PEM-formatted version of the credential chain.
 * - `cert`: Output variable; last certificate in creds.  Must be freed with
 *    X509_free.
 * - `chain`: Output variable; last N-1 certificates in creds.  Must be freed
 *    with sk_X509_free.
 * - `err_msg`: Output variable; contains error message on failure.  Must be
 *    freed with `free()`. 
 *
 * Returns false on failure.
 */
bool globus_get_cert_and_chain(const char * creds, size_t credslen, X509 **cert, STACK_OF(X509) **chain, char **err_msg);

#endif  // __GLOBUS_SUPPORT_H_
