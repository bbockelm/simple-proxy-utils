#include <string>
#include <vector>
#include <sstream>

#include <string.h>
#include <stdio.h>

#include <voms/voms_apic.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "GlobusSupport.hh"

/**
 * Verify a chain and extract the identity and the VOMS FQANs.
 *
 * - `cert` is the base64-encoded certificate chain.
 * - On success, if output variable `identity` is not null, it
 *   will be set to the proxy chain identity ("the DN").
 * - On success, if output variable `fqans` is not null, it will
 *   be set to a list of VOMS FQANs of length `fqans_count`.
 * - Returns non-zero on failure and sets output variable `err_msg`
 *   (if `err_msg` is not NULL); returns 0 otherwise.
 *
 * If any output variables are set, then the caller is responsible for
 * freeing the memory with `free`.  The `ident` and `fqans` variables
 * will only be set on success.
 */
const int FAIL_MEM = 2;
const int FAIL_CERT_CHAIN = 3;
const int FAIL_VERIFY_DN = 4;
const int FAIL_VOMS = 5;
const int FAIL_FQAN = 6;

extern "C" int
chain_verify(const char *cert, char **ident, char ***fqans, int *fqans_count, char **err_msg)
{
    int retval = 1;
    int voms_errcode = 0;
    ssize_t cert_len = -1;
    BIO* cert_bio = NULL;
    STACK_OF(X509) *cert_chain = NULL;
    X509* cert_ptr = NULL;
    char *dn = NULL;
    char **fqan_list = NULL;
    struct vomsdata *voms_ptr = NULL;
    std::vector<std::string> endorsements;

    if (!(cert_chain = sk_X509_new_null())) {
        if (err_msg) *err_msg = strdup("Failed to allocate memory for X509 chain.");
        retval = FAIL_MEM;
        goto cleanup;
    }

    cert_len = strlen(cert);

    // Parse the certificate chain.
    if (!globus_get_cert_and_chain(cert, cert_len, &cert_ptr, &cert_chain, err_msg)) {
        retval = FAIL_CERT_CHAIN;
        goto cleanup;
    }

    // Start with the DN extraction and proxy verification.
    if (!globus_verify(cert_ptr, cert_chain, &dn, err_msg)) {
        retval = FAIL_VERIFY_DN;
        goto cleanup;
    }

    // Parse VOMS data and append that.  Note that the lack of a VOMS extension (VERR_NOEXT) is not
    // fatal in our context.
    voms_ptr = VOMS_Init(NULL, NULL);
    if (!VOMS_Retrieve(cert_ptr, cert_chain, RECURSE_CHAIN, voms_ptr, &voms_errcode) && voms_errcode != VERR_NOEXT)
    {
        if (err_msg) {
            char *voms_err_msg = VOMS_ErrorMessage(voms_ptr, voms_errcode, NULL, 0);
            *err_msg = voms_err_msg ? voms_err_msg : strdup("VOMS AC retrieval failed");
        }
        retval = FAIL_VOMS;
        goto cleanup;
    }

    if (voms_errcode != VERR_NOEXT) {
        for (int idx = 0; voms_ptr->data[idx] != nullptr; idx++)
        {
            struct voms *it = voms_ptr->data[idx];
            if (!it->voname) {continue;}
            std::string base_key = "/";
            base_key +=  it->voname;
            base_key += "/";
            for (int idx2 = 0; it->std[idx2] != nullptr; idx2++)
            {
                struct data *it2 = it->std[idx2];
                if (!it2->group) {continue;}
                std::string key = it2->group;

                // Sanity check: does the group name make sense?  It must start with "/voname"
                if (key.size() + 1 < base_key.size()) {continue;} // group name is too short.
                if (key.size() + 1 == base_key.size() && strncmp(key.c_str(), base_key.c_str(), key.size())) {continue;}
                if (key.size() + 1 > base_key.size() && strncmp(key.c_str(), base_key.c_str(), base_key.size())) {continue;}

                // Log the role, provided it is present and not the word "NULL".
                if ((it2->role) && strcmp(it2->role, "NULL"))
                {
                    key += "/Role=";
                    key += it2->role;
                }
                endorsements.push_back(key);
            }
        }
    }

    // Return identity and VOMS FQANs.
    if (fqans && fqans_count) {
        fqan_list = static_cast<char**>(malloc((endorsements.size() + 1) * sizeof(char *)));
        if (!fqan_list) {
            if (err_msg) *err_msg = strdup("Failed to allocate memory for resulting FQANs.");
            retval = FAIL_FQAN;
            goto cleanup;
        }
        for (size_t idx = 0; idx < endorsements.size(); idx++) {
            fqan_list[idx] = strdup(endorsements[idx].c_str());
            if (!fqan_list[idx]) {
                if (err_msg) *err_msg = strdup("Failed to allocate memory for FQAN.");
                retval = FAIL_FQAN;
                goto cleanup;
            }
        }
        fqan_list[endorsements.size()] = '\0';
        *fqans = fqan_list;
        *fqans_count = endorsements.size();
        fqan_list = NULL;
    }
    if (ident) {
        *ident = dn;
        dn = NULL;
    }

    retval = 0;

cleanup:
    if (cert_bio) BIO_free(cert_bio);
    if (cert_chain) sk_X509_pop_free(cert_chain, X509_free);
    if (cert_ptr) X509_free(cert_ptr);
    if (dn) free(dn);
    if (voms_ptr) VOMS_Destroy(voms_ptr);
    if (fqan_list) {
        for (auto idx = 0; fqan_list[idx]; idx++) {
            free(fqan_list[idx]);
        }
        free(fqan_list);
    }

    return retval;
}

//
// Free up the returns FQANs structure contents.
extern "C" void
fqans_free(char **fqans) {
    for (auto idx = 0; fqans[idx]; idx++) {
            free(fqans[idx]);
    }
    free(fqans);
}
