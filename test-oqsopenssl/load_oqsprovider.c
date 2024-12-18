#include <stdio.h>
#include <stdlib.h> // For setenv
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

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
OSSL_PROVIDER *load_default_provider(OSSL_LIB_CTX *libctx) {
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "default");
    T(provider != NULL);
    printf("Default provider successfully loaded.\n");
    return provider;
}

/** \brief Load the OQS provider */
static OSSL_PROVIDER *load_oqs_provider(OSSL_LIB_CTX *libctx) {
    const char *provider_path = "/usr/local/lib64/ossl-modules";
    T(OSSL_PROVIDER_set_default_search_path(libctx, provider_path));
    printf("Provider search path set to: %s\n", provider_path);

    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
    T(provider != NULL);
    printf("OQS provider successfully loaded.\n");
    return provider;
}

/** \brief Perform ECDSA signature using the default provider */
static void perform_ecdsa_signature(OSSL_LIB_CTX *libctx) {
    printf("\nPerforming ECDSA signature...\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    T(pctx != NULL);

    T(EVP_PKEY_keygen_init(pctx) > 0);
    T(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) > 0);

    EVP_PKEY *ecdsa_key = NULL;
    T(EVP_PKEY_keygen(pctx, &ecdsa_key) > 0);

    printf("ECDSA key generated successfully.\n");

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(ecdsa_key);
}

/** \brief Perform Dilithium signature using the OQS provider */
static void perform_dilithium_signature(OSSL_LIB_CTX *libctx) {
    printf("\nPerforming Dilithium signature...\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "dilithium3", NULL);
    T(pctx != NULL);

    T(EVP_PKEY_keygen_init(pctx) > 0);

    EVP_PKEY *dilithium_key = NULL;
    T(EVP_PKEY_keygen(pctx, &dilithium_key) > 0);

    printf("Dilithium key generated successfully.\n");

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(dilithium_key);
}

int main() {
    // Create a new OpenSSL library context
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    T(libctx != NULL);

    // Load default provider
    OSSL_PROVIDER *default_provider = load_default_provider(libctx);

    // Load OQS provider
    OSSL_PROVIDER *oqs_provider = load_oqs_provider(libctx);

    // Perform ECDSA signature (from default provider)
    perform_ecdsa_signature(libctx);

    // Perform Dilithium signature (from OQS provider)
    perform_dilithium_signature(libctx);

    // Unload providers and free library context
    OSSL_PROVIDER_unload(default_provider);
    OSSL_PROVIDER_unload(oqs_provider);
    OSSL_LIB_CTX_free(libctx);

    printf("\nAll operations completed successfully.\n");
    return 0;
}
