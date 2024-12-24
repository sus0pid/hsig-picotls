//
// Created by xinshu on 24/12/24.
//

#ifndef HSIG_PICOTLS_OQS_UTIL_H
#define HSIG_PICOTLS_OQS_UTIL_H
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>

#define T(e)                                                                   \
    if (!(e)) {                                                                \
        ERR_print_errors_fp(stderr);                                           \
        OPENSSL_die(#e, __FILE__, __LINE__);                                   \
    }

#define TF(e)                                                                  \
    if ((e)) {                                                                 \
        ERR_print_errors_fp(stderr);                                           \
    } else {                                                                   \
        OPENSSL_die(#e, __FILE__, __LINE__);                                   \
    }

/** \brief Load the default OpenSSL provider */
OSSL_PROVIDER *load_default_provider(OSSL_LIB_CTX *libctx);

/** \brief Load the OQS provider */
OSSL_PROVIDER *load_oqs_provider(OSSL_LIB_CTX *libctx);


#endif // HSIG_PICOTLS_OQS_UTIL_H
