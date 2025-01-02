//
// Created by xinshu on 02/01/25.
//

#ifndef HSIG_PICOTLS_UTILITIES_H
#define HSIG_PICOTLS_UTILITIES_H
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <openssl/pem.h>
#include "picotls/pembase64.h"
#include "picotls/openssl.h"

enum Sig_schemes {
    DILITHIUM2,
    DILITHIUM3,
    DILITHIUM5,
    RSA,
    ECDSA,
    SIG_SCHEMES_COUNT
};

static const char *sig_names[] __attribute__((unused)) = {
    [DILITHIUM2] = "dilithium2",
    [DILITHIUM3] = "dilithium3",
    [DILITHIUM5] = "dilithium5",
    [RSA] = "rsa",
    [ECDSA] = "ecdsa",
};

_Static_assert(SIG_SCHEMES_COUNT ==
                   sizeof(sig_names) / sizeof(sig_names[0]),
               "sig_names[] and Sig_schemes enum must match");

static int get_signame(char const *sig_name) {
    for (int i = 0; i < SIG_SCHEMES_COUNT; i++) {
        if (strcmp(sig_name, sig_names[i]) == 0) return i;
    }
    return -1;
}

static void wrong_signame() {
    fprintf(stderr, "Unsupported signature scheme! (Choose from ");
    for (int i = 0; i < SIG_SCHEMES_COUNT; i++) {
        fprintf(stderr, "%s", sig_names[i]);
        if (i != SIG_SCHEMES_COUNT - 1) fprintf(stderr, ", ");
    }
    fprintf(stderr, ")\n");
}

static void setup_certificate(ptls_iovec_t *dst, const char *fn)
{
    FILE *fp;
    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "Failed to open cert file at %s\n", fn);
        exit(1);
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);
}

static inline void setup_private_key(ptls_openssl_sign_certificate_t *sc, const char *fn, const char *sig_name, int is_oqs_sig)
{
    FILE *fp;
    EVP_PKEY *pkey;

    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL) {
        fprintf(stderr, "failed to read private key from file:%s\n", fn);
        exit(1);
    }

    if (is_oqs_sig)
        ptls_openssl_init_oqs_sign_certificate(sc, pkey, sig_name);
    else
        ptls_openssl_init_trad_sign_certificate(sc, pkey);
    EVP_PKEY_free(pkey);
}

static inline X509_STORE *init_cert_store(char const *crt_file)
{
    int ret = 0;
    X509_STORE *store = X509_STORE_new();

    if (store != NULL) {
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        ret = X509_LOOKUP_load_file(lookup, crt_file, X509_FILETYPE_PEM);
        if (ret != 1) {
            fprintf(stderr, "Cannot load store (%s), ret = %d\n", crt_file, ret);
            X509_STORE_free(store);
            exit(1);
        }
    } else {
        fprintf(stderr, "Cannot get a new X509 store\n");
        exit(1);
    }
    printf("[%s]: using costomised cert store: %s, %d\n", __func__, crt_file, __LINE__);

    return store;
}



#endif // HSIG_PICOTLS_UTILITIES_H
