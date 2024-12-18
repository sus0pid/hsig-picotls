#include <stdio.h>
#include <stdlib.h> // For setenv
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

OSSL_PROVIDER *load_default_provider(OSSL_LIB_CTX *libctx) {
    OSSL_PROVIDER *provider;
    T((provider = OSSL_PROVIDER_load(libctx, "default")));
    return provider;
}

static int load_oqs_provider(OSSL_LIB_CTX *libctx) {
    // Set the default provider search path (optional)
    const char *provider_path = "/usr/local/lib64/ossl-modules";
    if (!OSSL_PROVIDER_set_default_search_path(libctx, provider_path)) {
        fprintf(stderr, "Failed to set default provider search path: %s\n", provider_path);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Provider search path set to: %s\n", provider_path);

    // Load the OQS provider
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (provider == NULL) {
        fprintf(stderr, "Failed to load the OQS provider.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("OQS provider successfully loaded.\n");
    return 0;
}

int main() {
    // create a new openssl lib context
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create OpenSSL library context.\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (load_oqs_provider(libctx) != 0) {
        fprintf(stderr, "Failed to load OQS provider.\n");
        return 2;
    }

    printf("OQS Provider loaded successfully.\n");

    OSSL_LIB_CTX_free(libctx);
    return 0;
}

