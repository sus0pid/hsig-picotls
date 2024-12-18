#include <stdio.h>
#include <stdlib.h> // For setenv
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

static const char *kOQSProviderName = "oqsprovider";

static int load_oqs_provider(OSSL_LIB_CTX *libctx) {
    OSSL_PROVIDER *provider;

    // Set the environment variable to point to the provider modules path
    if (setenv("OPENSSL_MODULES", "/usr/local/lib64/ossl-modules", 1) != 0) {
        fprintf(stderr, "Failed to set OPENSSL_MODULES environment variable.\n");
        return -1;
    }

    provider = OSSL_PROVIDER_load(libctx, kOQSProviderName);
    if (provider == NULL) {
        fprintf(stderr, "Failed to load provider '%s'.\n", kOQSProviderName);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("Provider '%s' successfully loaded.\n", kOQSProviderName);
    return 0;
}

int main() {
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

