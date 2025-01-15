//
// Created by xinshu on 06/01/25.
//
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include "../lib/openssl.c"
#include "oqs_util.h"
#include "bench_common.h"

#define BENCH_BATCH 64

/*TODO: bench certificate verification
 * current cert: rsa, dilithium3 */

/* Single measurement.
 * for each schemes, we only bench schemes[0], refer to rsa_signature_schemes[] in lib/openssl.c */
static int bench_run_one(EVP_PKEY *key, const ptls_openssl_signature_scheme_t *schemes, size_t n,
                         uint64_t *t_sign, uint64_t *t_verify, int is_oqs_sig)
{
    int ret = 0;
//    printf("benchmark scheme: 0x%04x", schemes[0].scheme_id);
    const void *message = "hello world";
    size_t message_len = strlen(message);
    ptls_buffer_t sigbuf;
    uint8_t sigbuf_small[1024];

    *t_sign = 0;
    *t_verify = 0;

    for (size_t k = 0; k < n;) {
        size_t i_max = ((n - k) > BENCH_BATCH) ? BENCH_BATCH : (n - k);
        uint64_t t_start = bench_time();
        uint64_t t_medium, t_end;
        ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));
        /* Benchmark signing in batch */
        for (size_t i = 0; i < i_max; i++) {
            if (i) {
                ptls_buffer_dispose(&sigbuf);
                ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));
            }
            if (!is_oqs_sig)
                ret = do_sign(key, schemes, &sigbuf, ptls_iovec_init(message, message_len), NULL);
            else if (is_oqs_sig == 1)
                ret = do_oqs_sign(key, schemes, &sigbuf, ptls_iovec_init(message, message_len), NULL);
            else if (is_oqs_sig == 2)
                ret = do_art_sign(key, schemes, &sigbuf, ptls_iovec_init(message, message_len), NULL);
            if (ret != 0) {
                fprintf(stderr, "do_sign failed at iteration %zu\n", k + i);
                goto Cleanup;
            }
        }

        t_medium = bench_time();

        /* Benchmark verification in batch */
        for (size_t i = 0; i < i_max; i++) {
            EVP_PKEY_up_ref(key);
            if (!is_oqs_sig)
                ret = verify_sign(key, schemes[0].scheme_id, ptls_iovec_init(message, message_len),
                              ptls_iovec_init(sigbuf.base, sigbuf.off));
            else if (is_oqs_sig == 1)
                ret = verify_oqs_sign(key, schemes[0].scheme_id, ptls_iovec_init(message, message_len),
                                  ptls_iovec_init(sigbuf.base, sigbuf.off));
            else if (is_oqs_sig == 2)
                ret = verify_art_sign(key, schemes[0].scheme_id, ptls_iovec_init(message, message_len),
                                      ptls_iovec_init(sigbuf.base, sigbuf.off));
            if (ret != 0) {
                fprintf(stderr, "verify_sign failed at iteration %zu\n", k + i);
                goto Cleanup;
            }
        }

        t_end = bench_time();

        *t_sign += t_medium - t_start;
        *t_verify += t_end - t_medium;

        k += i_max;
    }

Cleanup:
    ptls_buffer_dispose(&sigbuf);
    return ret;
}


/* Measure one sign and verify implementation */
static int bench_sign_verify(char *OS, char *HW, int basic_ref, const char *provider, const char *sig_name,
                             const ptls_openssl_signature_scheme_t *schemes, size_t n)
{
    int ret = 0;
    uint64_t t_sign = 0;
    uint64_t t_verify = 0;
    char p_version[128];
    int is_oqs_sig = 0;

    /* Document library version as it may have impact on performance */
    p_version[0] = 0;

    /*
     * OPENSSL_VERSION_NUMBER is a combination of the major, minor and patch version
     * into a single integer 0xMNNFFPP0L, where M is major, NN is minor, PP is patch
     */
    uint32_t combined = OPENSSL_VERSION_NUMBER;
    int M = combined >> 28;
    int NN = (combined >> 20) & 0xFF;
    int FF = (combined >> 12) & 0xFF;
    int PP = (combined >> 4) & 0xFF;
    char letter = 'a' - 1 + PP;
    (void)sprintf(p_version, "%d.%d.%d%c", M, NN, FF, letter);

    /* create pkey
     * rsa2048, ecdsa256(secp256r1)
     * rsa3072, ecdsa384(secp384r1)*/
    EVP_PKEY *pkey = NULL;
    if (strcmp(sig_name, "rsa") == 0) {
        int rsa_bits = 2048;
        /* Create the context for key generation */
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
            fprintf(stderr, "Failed to initialize rsa keygen context\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        /* Set the RSA key size */
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, rsa_bits) <= 0) {
            fprintf(stderr, "Failed to set RSA key size\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        /* Generate the RSA key */
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            fprintf(stderr, "Failed to generate RSA key\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        EVP_PKEY_CTX_free(pctx);
    }
    else if (strcmp(sig_name, "ecdsa") == 0) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
            fprintf(stderr, "Failed to initialize ECDSA key generation context\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
            fprintf(stderr, "Failed to set EC curve\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            fprintf(stderr, "Failed to generate ECDSA key\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        EVP_PKEY_CTX_free(pctx);
    }
    else if (strcmp(sig_name, "ed25519") == 0) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
            fprintf(stderr, "Failed to initialize ed25519 keygen context\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            fprintf(stderr, "Failed to generate RSA key\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        EVP_PKEY_CTX_free(pctx);
    }
    else if (strncmp(sig_name, "dilithium", 3) == 0) {
        is_oqs_sig = 1;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, sig_name, NULL);
        if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
            fprintf(stderr, "Failed to initialize Dilithium keygen context.\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        if (EVP_PKEY_generate(pctx, &pkey) <= 0)
            fprintf(stderr, "Failed to generate Dilithium key.\n");
        EVP_PKEY_CTX_free(pctx);
    }
    else if (strcmp(sig_name, "hsig") == 0) {
        is_oqs_sig = 2;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "dilithium2", NULL);
        if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
            fprintf(stderr, "Failed to initialize Dilithium keygen context.\n");
            EVP_PKEY_CTX_free(pctx);
            exit(1);
        }
        if (EVP_PKEY_generate(pctx, &pkey) <= 0)
            fprintf(stderr, "Failed to generate Dilithium key.\n");
        EVP_PKEY_CTX_free(pctx);
    }


    if (pkey == NULL || schemes == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    } else {
        ret = bench_run_one(pkey, schemes, n, &t_sign, &t_verify, is_oqs_sig);
        if (ret == 0) {
            double avg_t_sign = (double)t_sign / n;  // Average time per signing (in microseconds)
            double avg_t_verify = (double)t_verify / n;  // Average time per verification (in microseconds)

            printf("%s, %s, %d, %d, %s, %s, %s, %d, %.2f, %.2f, %.2f, %.2f\n", OS, HW, (int)(8 * sizeof(size_t)),
                   basic_ref, provider, p_version, sig_name, (int)n, avg_t_sign, avg_t_verify,
                   1000000.0 / avg_t_sign, 1000000.0 / avg_t_verify);
        }
    }
    EVP_PKEY_free(pkey);
    return ret;
}

int main(int argc, char **argv)
{
    // Create a new OpenSSL library context
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    T(libctx != NULL);
    // Load default provider
    OSSL_PROVIDER *default_provider = load_default_provider(libctx);
    // Load OQS provider
    OSSL_PROVIDER *oqs_provider = load_oqs_provider(libctx);

    int ret = 0;
    int force_all_tests = 0;
    uint64_t x = 0xdeadbeef;
    struct utsname uts;
    int basic_ref = bench_basic(&x);
    char OS[128];
    char HW[128];

    OS[0] = 0;
    HW[0] = 0;
    if (uname(&uts) == 0) {
        if (strlen(uts.sysname) + 1 < sizeof(OS)) {
            strcpy(OS, uts.sysname);
        }
        if (strlen(uts.machine) + 1 < sizeof(HW)) {
            strcpy(HW, uts.machine);
        }
    }

    if (argc == 2 && strcmp(argv[1], "-f") == 0) {
        force_all_tests = 1;
    } else if (argc > 1) {
        fprintf(stderr, "Usage: %s [-f]\n   Use option \"-f\" to force execution of the slower tests.\n", argv[0]);
        exit(-1);
    }

    printf(
        "OS, HW, bits, 10M ops, provider, version, algorithm, N, sign us, verify us, sign opps, verify opbps,\n");

    for (size_t i = 0; ret == 0 && i < nb_sig_list; i++) {
        if (sig_list[i].enabled_by_default || force_all_tests) {
            ret = bench_sign_verify(OS, HW, basic_ref, sig_list[i].provider, sig_list[i].sig_name,
                                    sig_list[i].schemes, 100000); /*options: 100000, 1000000, 1000*/
        }
    }

    // Unload providers and free library context
    OSSL_PROVIDER_unload(default_provider);
    OSSL_PROVIDER_unload(oqs_provider);
    OSSL_LIB_CTX_free(libctx);

    return ret;
}