#include <stdio.h>
#include <stdlib.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/** \brief Helper function to print OpenSSL errors */
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main() {
    // Step 1: Create a new OpenSSL library context
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create OpenSSL library context.\n");
        handle_openssl_error();
    }

    // Step 2: Set the default provider search path (optional)
    const char *provider_path = "/usr/local/lib64/ossl-modules";
    if (!OSSL_PROVIDER_set_default_search_path(libctx, provider_path)) {
        fprintf(stderr, "Failed to set default provider search path: %s\n", provider_path);
        handle_openssl_error();
    }
    printf("Provider search path set to: %s\n", provider_path);

    // Step 3: Load the OQS provider
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (provider == NULL) {
        fprintf(stderr, "Failed to load the OQS provider.\n");
        handle_openssl_error();
    }
    printf("OQS provider successfully loaded.\n");

    // Step 4: Clean up
    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(libctx);

    printf("All operations completed successfully.\n");
    return 0;
}

