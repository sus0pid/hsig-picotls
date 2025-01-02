//
// Created by xinshu on 02/01/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/provider.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "utilities.h"

static void client_usage(const char *cmd) {
    printf("Client Usage: %s [options] host port protocol\n"
           "\n"
           "host:                IP address of server\n"
           "port:                port number of server\n"
           "signature name:      dilithium3, dilithium2, dilithium5, rsa, ecdsa\n" // this decides which server cert to load
           "Options:\n"
           "-p                   use post-quantum signature schemes\n"
           "-m                   require mutual authentication\n"
           "-n size              message size (Bytes) of the first app data\n"
           "-h                   print this help\n", cmd);
    printf("\n\n");
}

int main(int argc, char **argv) {

    /* load algos*/
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Explicitly load the oqs provider, as we test oqs in the tests */
    // Set the default search path for providers
    const char *provider_path = "/usr/local/lib64/ossl-modules";
    if (!OSSL_PROVIDER_set_default_search_path(NULL, provider_path)) {
        fprintf(stderr, "Failed to set provider search path: %s\n", provider_path);
        exit(1);
    }
    printf("Provider search path set to: %s\n", provider_path);
    // Load the OQS provider into the default context
    OSSL_PROVIDER *oqsprovider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (oqsprovider == NULL) {
        fprintf(stderr, "Failed to load OQS provider.\n");
        exit(1);
    }
    printf("OQS provider successfully loaded.\n");
    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(NULL, "default");
#elif !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    res_init();

    if (argc < 3) {
        client_usage(argv[0]);
        goto Exit;
    }

    int ch, message_size, is_oqs_sig, is_mutual_auth;
    while ((ch = getopt(argc, argv, "n:pmh")) != -1) {
        switch (ch) {
        case 'p':
            is_oqs_sig = 1;
            printf("setting: use post-quantum signature algorithm\n");
            break;
        case 'm':
            is_mutual_auth = 1;
            printf("setting: mutual authentication mode\n");
            break;
        case 'n':
            message_size = atoi(optarg);
            printf("setting: message_size: %d bytes\n", message_size);
            break;
        case 'h':
            client_usage(argv[0]);
            goto Exit;
        default:
            goto Exit;
        }
    }
    argc -= optind;
    argv += optind;

    const char *host, *port, *sig_name;
    host = (--argc, *argv++);
    port = (--argc, *argv++);
    sig_name = (--argc, *argv++);
    size_t sig_index = get_signame(sig_name);
    if (sig_index == -1) {
        wrong_signame();
        goto Exit;
    }

    char certpath[300];
    char privkeypath[300];
    char capath[300];
    const char *sep = "/"; /*for most systems like linux, macos*/
    char *certsdir = "assets/";

    if (!is_oqs_sig)
    {
        /* traditional signature algos */
        sprintf(certpath, "%s%s%s%s", certsdir, sig_name, sep, "cert.pem");
        sprintf(privkeypath, "%s%s%s%s", certsdir, sig_name, sep, "key.pem");
        sprintf(capath, "%s%s%s%s", certsdir, "ca", sep, "test-ca.crt");
    } else
    {
        /* post quantum signature algos */
        sprintf(certpath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.crt");
        sprintf(privkeypath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.key");
        sprintf(capath, "%s%s%s%s", certsdir, "oqs-ca", sep, "dilithium3_CA.crt");
    }
    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;
    ptls_iovec_t cert;

    if (is_mutual_auth)
    {
        setup_certificate(&cert, certpath);
        setup_private_key(&openssl_sign_certificate, privkeypath, sig_name, is_oqs_sig);
    }
    /* setup ca cert file */
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, init_cert_store(capath));

    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges, /*ptls_openssl_key_exchanges by default*/
                          .cipher_suites = ptls_openssl_cipher_suites_all, /*ptls_openssl_cipher_suites_all by default*/
                          .certificates = {&cert, 1},
                          .ech = {.client = {NULL}}, /* no ech */
                          .sign_certificate = &openssl_sign_certificate.super,
                          .verify_certificate = &openssl_verify_certificate.super};
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}}}};

    /* setup log*/

    /* run client */
    int ret;
    

Exit:
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(oqsprovider);
#endif
    exit(1);
}
