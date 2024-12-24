//
// Created by xinshu on 24/12/24.
// gcc -o dynamic_oqsprovider dynamic_oqsprovider.c -I/usr/local/include -L/usr/local/lib64 -lssl -lcrypto -ldl
//
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "oqs_util.h"

static OSSL_LIB_CTX *libctx = NULL;

/* Stolen from openssl/tests/sslapitest.c: */
int create_cert_key(OSSL_LIB_CTX *libctx, char *algname, char *certfilename,
                    char *privkeyfilename) {
    EVP_PKEY_CTX *evpctx = EVP_PKEY_CTX_new_from_name(libctx, algname, NULL);
    EVP_PKEY *pkey = NULL;
    X509 *x509 = X509_new();
    X509_NAME *name = NULL;
    BIO *keybio = NULL, *certbio = NULL;
    int ret = 1;

    if (!evpctx || !EVP_PKEY_keygen_init(evpctx) ||
        !EVP_PKEY_generate(evpctx, &pkey) || !pkey || !x509 ||
        !ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) ||
        !X509_gmtime_adj(X509_getm_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L) ||
        !X509_set_pubkey(x509, pkey) || !(name = X509_get_subject_name(x509)) ||
        !X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                    (unsigned char *)"CH", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    (unsigned char *)"test.org", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"localhost", -1, -1, 0) ||
        !X509_set_issuer_name(x509, name) ||
        !X509_sign(x509, pkey, EVP_sha256()) ||
        !(keybio = BIO_new_file(privkeyfilename, "wb")) ||
        !PEM_write_bio_PrivateKey(keybio, pkey, NULL, NULL, 0, NULL, NULL) ||
        !(certbio = BIO_new_file(certfilename, "wb")) ||
        !PEM_write_bio_X509(certbio, x509))
        ret = 0;

    EVP_PKEY_free(pkey);
    X509_free(x509);
    EVP_PKEY_CTX_free(evpctx);
    BIO_free(keybio);
    BIO_free(certbio);
    return ret;
}

int main() {
    int ret = 0;
    char certpath[300];
    char privkeypath[300];
#ifndef OPENSSL_SYS_VMS
    const char *sep = "/";
#else
    const char *sep = "";
#endif

    char *certsdir = "certs";
    char *sig_name = "dilithium2";
    sprintf(certpath, "%s%s%s%s", certsdir, sep, sig_name, "_cert.pem");
    sprintf(privkeypath, "%s%s%s%s", certsdir, sep, sig_name, "_key.pem");
    if (mkdir(certsdir, 0700)) {
        if (errno != EEXIST) {
            fprintf(stderr, "Couldn't create certsdir %s: Err = %d\n", certsdir,
                    errno);
            ret = -1;
            goto err;
        }
    }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    // Load default provider
    OSSL_PROVIDER *default_provider = load_default_provider(libctx);
    // Load OQS provider
    OSSL_PROVIDER *oqs_provider = load_oqs_provider(libctx);

    if (!create_cert_key(libctx, (char *)sig_name, certpath, privkeypath)) {
        fprintf(stderr, "Cert/keygen failed for %s at %s/%s\n", sig_name,
                certpath, privkeypath);
        ret = -1;
        goto err;
    }

err:
    return ret;
}