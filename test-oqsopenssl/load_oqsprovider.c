/*gcc -o dynamic_oqsprovider dynamic_oqsprovider.c -I/usr/local/include -L/usr/local/lib64 -lssl -lcrypto -ldl
 */
#include <stdio.h>
#include <stdlib.h> // For setenv
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

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


OSSL_PROVIDER *load_default_provider(OSSL_LIB_CTX *libctx) {
    OSSL_PROVIDER *provider;
    T((provider = OSSL_PROVIDER_load(libctx, "default")));
    return provider;
}

static int load_oqs_provider(OSSL_LIB_CTX *libctx) {
    // Set the default provider search path (optional)
    const char *provider_path = "/usr/local/lib64/ossl-modules";
    T(OSSL_PROVIDER_set_default_search_path(libctx, provider_path));
    printf("Provider search path set to: %s\n", provider_path);

    // Load the OQS provider
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
    T(provider != NULL);
    printf("OQS provider successfully loaded.\n");
    return 0;
}

int main() {
    // create a new openssl lib context
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    T (libctx != NULL);

    if (load_oqs_provider(libctx) != 0) {
        fprintf(stderr, "Failed to load OQS provider.\n");
        return 2;
    }

    printf("OQS Provider loaded successfully.\n");

    OSSL_LIB_CTX_free(libctx);
    return 0;
}

