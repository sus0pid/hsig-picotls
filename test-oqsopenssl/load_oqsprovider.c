// gcc -o dynamic_oqsprovider dynamic_oqsprovider.c -I/usr/local/include -L/usr/local/lib64 -lssl -lcrypto -ldl
#include <stdio.h>
#include <stdlib.h> // For setenv
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>


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
//    T(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) > 0); /*legacy version 1.1.1*/
    // Set curve parameters using EVP_PKEY_CTX_set_params
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", "secp256k1", 0),
        OSSL_PARAM_construct_end()
    };
    T(EVP_PKEY_CTX_set_params(pctx, params) > 0);

    EVP_PKEY *ecdsa_key = NULL;
    T(EVP_PKEY_keygen(pctx, &ecdsa_key) > 0);

    printf("ECDSA key generated successfully.\n");

    // Output the EVP_PKEY_id() of the generated Dilithium key
    int key_id = EVP_PKEY_id(ecdsa_key);
    printf("EVP_PKEY_id of ecdsa key: %d\n", key_id);

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

    // Output the EVP_PKEY_id() of the generated Dilithium key
    int key_id = EVP_PKEY_id(dilithium_key);
    printf("EVP_PKEY_id of Dilithium key: %d\n", key_id);

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(dilithium_key);
}

/** \brief Perform Falcon signature using the OQS provider */
static void perform_falcon_signature(OSSL_LIB_CTX *libctx) {
    printf("\nPerforming Falcon signature...\n");

    // Create a key generation context for Falcon
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "falcon512", NULL);
    T(pctx != NULL);

    // Initialize the key generation context
    T(EVP_PKEY_keygen_init(pctx) > 0);

    // Generate the Falcon key
    EVP_PKEY *falcon_key = NULL;
    T(EVP_PKEY_keygen(pctx, &falcon_key) > 0);
    printf("Falcon key generated successfully.\n");

    // Output the EVP_PKEY_id() of the generated Falcon key
    int key_id = EVP_PKEY_id(falcon_key);
    printf("EVP_PKEY_id of Falcon key: %d\n", key_id);

    // Clean up
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(falcon_key);
}

/** \brief Generate Dilithium key and certificate */
static void generate_dilithium_cert_and_key(OSSL_LIB_CTX *libctx, const char *certfile, const char *keyfile) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "dilithium3", NULL);
    T(pctx != NULL);
    T(EVP_PKEY_keygen_init(pctx) > 0);

    EVP_PKEY *dilithium_key = NULL;
    T(EVP_PKEY_keygen(pctx, &dilithium_key) > 0);

    // Save private key to file
    FILE *key_fp = fopen(keyfile, "w");
    T(key_fp != NULL);
    T(PEM_write_PrivateKey(key_fp, dilithium_key, NULL, NULL, 0, NULL, NULL));
    fclose(key_fp);

    // Create certificate
    X509 *x509 = X509_new();
    T(x509 != NULL);
    T(ASN1_INTEGER_set(X509_get_serialNumber(x509), 1));
    T(X509_gmtime_adj(X509_getm_notBefore(x509), 0));
    T(X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L));
    T(X509_set_pubkey(x509, dilithium_key));

    X509_NAME *name = X509_get_subject_name(x509);
    T(name != NULL);
    T(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0));
    T(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Example Org", -1, -1, 0));
    T(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0));
    T(X509_set_issuer_name(x509, name));
    T(X509_sign(x509, dilithium_key, EVP_sha256()));

    // Save certificate to file
    FILE *cert_fp = fopen(certfile, "w");
    T(cert_fp != NULL);
    T(PEM_write_X509(cert_fp, x509));
    fclose(cert_fp);

    // Clean up
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(dilithium_key);
    X509_free(x509);

    printf("Dilithium certificate and key generated successfully.\n");
}

/** \brief Read the Dilithium private key and output its algorithm */
static void read_dilithium_private_key(const char *keyfile) {
    FILE *key_fp = fopen(keyfile, "r");
    T(key_fp != NULL);

    EVP_PKEY *key = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);
    T(key != NULL);

    int key_type = EVP_PKEY_base_id(key);
    printf("Private key type: %d\n", key_type);

    EVP_PKEY_free(key);
}

/** \brief Read the Dilithium certificate and output its signature algorithm */
static void read_dilithium_certificate(const char *certfile) {
    FILE *cert_fp = fopen(certfile, "r");
    T(cert_fp != NULL);

    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    T(cert != NULL);

    int sig_nid = X509_get_signature_nid(cert);
    printf("Certificate signature algorithm NID: %d\n", sig_nid);
    printf("Signature algorithm: %s\n", OBJ_nid2ln(sig_nid));

    X509_free(cert);
}



int main() {
    // Create a new OpenSSL library context
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    T(libctx != NULL);

    // Load default provider
    OSSL_PROVIDER *default_provider = load_default_provider(libctx);

    // Load OQS provider
    OSSL_PROVIDER *oqs_provider = load_oqs_provider(libctx);

//    // Perform ECDSA signature (from default provider)
//    perform_ecdsa_signature(libctx);
//
//    // Perform Dilithium signature (from OQS provider)
//    perform_dilithium_signature(libctx);
//
//    perform_falcon_signature(libctx);

    // Generate Dilithium certificate and key
    const char *certfile = "dilithium_cert.pem";
    const char *keyfile = "dilithium_key.pem";
    generate_dilithium_cert_and_key(libctx, certfile, keyfile);

    // Read and log details of the private key
    read_dilithium_private_key(keyfile);

    // Read and log details of the certificate
    read_dilithium_certificate(certfile);

    // Unload providers and free library context
    OSSL_PROVIDER_unload(default_provider);
    OSSL_PROVIDER_unload(oqs_provider);
    OSSL_LIB_CTX_free(libctx);

    printf("\nAll operations completed successfully.\n");
    return 0;
}
