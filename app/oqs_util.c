//
// Created by xinshu on 24/12/24.
//
#include <string.h>
#include "oqs_util.h"

/** \brief Load the default OpenSSL provider */
OSSL_PROVIDER *load_default_provider(OSSL_LIB_CTX *libctx) {
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "default");
    T(provider != NULL);
    printf("Default provider successfully loaded.\n");
    return provider;
}

/** \brief Load the OQS provider */
OSSL_PROVIDER *load_oqs_provider(OSSL_LIB_CTX *libctx) {
    const char *provider_path = "/usr/local/lib64/ossl-modules";
    T(OSSL_PROVIDER_set_default_search_path(libctx, provider_path));
    printf("Provider search path set to: %s\n", provider_path);

    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
    T(provider != NULL);
    printf("OQS provider successfully loaded.\n");
    return provider;
}