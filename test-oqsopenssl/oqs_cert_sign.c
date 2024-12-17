#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main() {
    // Step 1: Initialize OpenSSL library context and load oqsprovider
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        fprintf(stderr, "Failed to create OpenSSL library context.\n");
        return 1;
    }

    OSSL_PROVIDER *oqs_provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (!oqs_provider) {
        fprintf(stderr, "Failed to load oqsprovider.\n");
        handle_openssl_error();
    }
    printf("Loaded oqsprovider successfully.\n");

    // Step 2: Generate Dilithium3 key pair
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_from_name(libctx, "dilithium3", NULL);
    if (!pkey_ctx) {
        fprintf(stderr, "Failed to create PKEY context for Dilithium3.\n");
        handle_openssl_error();
    }

    EVP_PKEY *keypair = NULL;
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0 || EVP_PKEY_generate(pkey_ctx, &keypair) <= 0) {
        fprintf(stderr, "Key generation failed.\n");
        handle_openssl_error();
    }
    printf("Dilithium3 key pair generated successfully.\n");

    // Step 3: Create a self-signed certificate
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Failed to create certificate.\n");
        handle_openssl_error();
    }

    // Set certificate details
    X509_set_version(cert, 2);  // Version 3 certificate
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);  // 1 year validity
    X509_set_pubkey(cert, keypair);

    // Set subject and issuer name
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Test CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // Sign the certificate
    if (X509_sign(cert, keypair, NULL) == 0) {
        fprintf(stderr, "Failed to sign certificate.\n");
        handle_openssl_error();
    }
    printf("Certificate created and signed successfully.\n");

    // Write certificate and key to files
    FILE *keyfile = fopen("dilithium3_CA.key", "wb");
    FILE *certfile = fopen("dilithium3_CA.crt", "wb");
    if (!keyfile || !certfile) {
        fprintf(stderr, "Failed to open output files.\n");
        handle_openssl_error();
    }
    PEM_write_PrivateKey(keyfile, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_X509(certfile, cert);
    fclose(keyfile);
    fclose(certfile);
    printf("Certificate and key saved to dilithium3_CA.crt and dilithium3_CA.key.\n");

    // Step 4: Sign a message
    const char *message = "This is a test message.";
    size_t message_len = strlen(message);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    EVP_DigestSignInit_ex(md_ctx, NULL, "SHA256", libctx, NULL, keypair);
    EVP_DigestSign(md_ctx, NULL, &sig_len, (unsigned char *)message, message_len);

    unsigned char *signature = OPENSSL_malloc(sig_len);
    EVP_DigestSign(md_ctx, signature, &sig_len, (unsigned char *)message, message_len);
    printf("Message signed successfully. Signature length: %zu bytes.\n", sig_len);

    // Step 5: Verify the signature using the certificate
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    EVP_DigestVerifyInit_ex(verify_ctx, NULL, "SHA256", libctx, NULL, pubkey);
    int verify_result = EVP_DigestVerify(verify_ctx, signature, sig_len, (unsigned char *)message, message_len);

    if (verify_result == 1) {
        printf("Signature verification successful.\n");
    } else {
        printf("Signature verification failed.\n");
    }

    // Clean up
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(keypair);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    X509_free(cert);
    OPENSSL_free(signature);
    OSSL_PROVIDER_unload(oqs_provider);
    OSSL_LIB_CTX_free(libctx);

    printf("All operations completed successfully.\n");
    return 0;
}
