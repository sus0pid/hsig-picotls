//
// Created by xinshu on 04/01/25.
gcc -o xxxxx xxxxx.c -I/usr/local/include -L/usr/local/lib64 -lssl -lcrypto -ldl
//
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

int test_x509_store_ctx_init(const char *cert_file, const char *ca_file) {
    int ret = -1;
    X509 *cert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    FILE *fp = NULL;

    // Load the certificate to be verified
    if ((fp = fopen(cert_file, "r")) == NULL) {
        fprintf(stderr, "Failed to open certificate file: %s\n", cert_file);
        goto Cleanup;
    }
    if ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "Failed to read certificate from file: %s\n", cert_file);
        ERR_print_errors_fp(stderr);
        goto Cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Create and load the store with the CA certificate
    if ((store = X509_STORE_new()) == NULL) {
        fprintf(stderr, "Failed to create X509_STORE\n");
        ERR_print_errors_fp(stderr);
        goto Cleanup;
    }
    if (X509_STORE_load_locations(store, ca_file, NULL) != 1) {
        fprintf(stderr, "Failed to load CA certificates from file: %s\n", ca_file);
        ERR_print_errors_fp(stderr);
        goto Cleanup;
    }

    // Create the X509_STORE_CTX
    if ((ctx = X509_STORE_CTX_new()) == NULL) {
        fprintf(stderr, "Failed to create X509_STORE_CTX\n");
        ERR_print_errors_fp(stderr);
        goto Cleanup;
    }

    // Initialize the context
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "X509_STORE_CTX_init failed\n");
        ERR_print_errors_fp(stderr);
        goto Cleanup;
    }

    printf("X509_STORE_CTX_init succeeded\n");
    ret = 0;

Cleanup:
    if (fp != NULL) fclose(fp);
    if (cert != NULL) X509_free(cert);
    if (store != NULL) X509_STORE_free(store);
    if (ctx != NULL) X509_STORE_CTX_free(ctx);

    return ret;
}

int main() {
    const char *cert_file = "assets/rsa/cert.pem";
    const char *ca_file = "assets/ca/test-ca.crt";

    if (test_x509_store_ctx_init(cert_file, ca_file) == 0) {
        printf("X509_STORE_CTX_init test passed\n");
    } else {
        printf("X509_STORE_CTX_init test failed\n");
    }

    return 0;
}

