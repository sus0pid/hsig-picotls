//
// Created by xinshu on 21/03/24.
//
#include "picotls.h"
#include "picotls/openssl.h"
#ifndef SDP_HANDSHAKE_TEST_PICOTLS_API_H
#define SDP_HANDSHAKE_TEST_PICOTLS_API_H

/* test vector using RFC 9180 A.3 */
#define ECH_CONFIG_LIST                                                                                                            \
    "\x00\x63\xfe\x0d\x00\x5f\x12\x00\x10\x00\x41\x04\xfe\x8c\x19\xce\x09\x05\x19\x1e\xbc\x29\x8a\x92\x45\x79\x25\x31\xf2\x6f\x0c" \
    "\xec\xe2\x46\x06\x39\xe8\xbc\x39\xcb\x7f\x70\x6a\x82\x6a\x77\x9b\x4c\xf9\x69\xb8\xa0\xe5\x39\xc7\xf6\x2f\xb3\xd3\x0a\xd6\xaa" \
    "\x8f\x80\xe3\x0f\x1d\x12\x8a\xaf\xd6\x8a\x2c\xe7\x2e\xa0\x00\x08\x00\x02\x00\x02\x00\x01\x00\x01\x40\x0b\x65\x78\x61\x6d\x70" \
    "\x6c\x65\x2e\x63\x6f\x6d\x00\x00"
/* another config using different ID and public key */
#define ECH_ALTERNATIVE_CONFIG_LIST                                                                                                \
    "\x00\x63\xfe\x0d\x00\x5f\x13\x00\x10\x00\x41\x04\x39\xd2\xc8\xfb\x6f\xcc\x79\x72\xb2\x28\x20\x33\xad\xc4\x97\x01\xff\xd6\x91" \
    "\x76\xaa\x1a\x11\xd9\x36\x51\xb1\xb1\x29\xd9\x0e\xe0\x96\x1f\x75\xfa\x19\xff\xec\xe2\xd7\x91\xab\xf5\x29\x39\x35\x66\x90\xbf" \
    "\xf3\x56\x73\xcf\xc1\x42\xc1\x6e\x99\x25\xd2\xab\xdb\xb6\x00\x08\x00\x02\x00\x02\x00\x01\x00\x01\x40\x0b\x65\x78\x61\x6d\x70" \
    "\x6c\x65\x2e\x63\x6f\x6d\x00\x00"
#define ECH_PRIVATE_KEY                                                                                                            \
    "-----BEGIN PRIVATE KEY-----\n"                                                                                                \
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg885/2uV+GjENh/Hr\n"                                                           \
    "vebzKL4Kmc28rfTWWJzyneS4/9KhRANCAAT+jBnOCQUZHrwpipJFeSUx8m8M7OJG\n"                                                           \
    "BjnovDnLf3Bqgmp3m0z5abig5TnH9i+z0wrWqo+A4w8dEoqv1oos5y6g\n"                                                                   \
    "-----END PRIVATE KEY-----\n"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEowIBAAKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6\n"                                                           \
    "A/Z+bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9\n"                                                           \
    "C7WcNcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7\n"                                                           \
    "ntPW/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDy\n"                                                           \
    "OxiNkLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MI\n"                                                           \
    "uDo7Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABAoIBAQCWcUv1wjR/2+Nw\n"                                                           \
    "B+Swp267R9bt8pdxyK6f5yKrskGErremiFygMrFtVBQYjws9CsRjISehSkN4GqjE\n"                                                           \
    "CweygJZVJeL++YvUmQnvFJSzgCjXU6GEStbOKD/A7T5sa0fmzMhOE907V+kpAT3x\n"                                                           \
    "E1rNRaP/ImJ1X1GjuefVb0rOPiK/dehFQWfsUkOvh+J3PU76wcnexxzJgxhVxdfX\n"                                                           \
    "qNa7UDsWzTImUjcHIfnhXc1K/oSKk6HjImQi/oE4lgoJUCEDaUbq0nXNrM0EmTTv\n"                                                           \
    "OQ5TVP5Lds9p8UDEa55eZllGXam0zKjhDKtkQ/5UfnxsAv2adY5cuH+XN0ExfKD8\n"                                                           \
    "wIZ5qINtAoGBAPRbQGZZkP/HOYA4YZ9HYAUQwFS9IZrQ8Y7C/UbL01Xli13nKalH\n"                                                           \
    "xXdG6Zv6Yv0FCJKA3N945lEof9rwriwhuZbyrA1TcKok/s7HR8Bhcsm2DzRD5OiC\n"                                                           \
    "3HK+Xy+6fBaMebffqBPp3Lfj/lSPNt0w/8DdrKBTw/cAy40g0n1zEu07AoGBAPHJ\n"                                                           \
    "V4IfQBiblCqDh77FfQRUNR4hVbbl00Gviigiw563nk7sxdrOJ1edTyTOUBHtM3zg\n"                                                           \
    "AT9sYz2CUXvsyEPqzMDANWMb9e2R//NcP6aM4k7WQRnwkZkp0WOIH95U2o1MHCYc\n"                                                           \
    "5meAHVf2UMl+64xU2ZfY3rjMmPLjWMt0hKYsOmtvAoGAClIQVkJSLXtsok2/Ucrh\n"                                                           \
    "81TRysJyOOe6TB1QNT1Gn8oiKMUqrUuqu27zTvM0WxtrUUTAD3A7yhG71LN1p8eE\n"                                                           \
    "3ytAuQ9dItKNMI6aKTX0czCNU9fKQ0fDp9UCkDGALDOisHFx1+V4vQuUIl4qIw1+\n"                                                           \
    "v9adA+iFzljqP/uy6DmEAyECgYAyWCgecf9YoFxzlbuYH2rukdIVmf9M/AHG9ZQg\n"                                                           \
    "00xEKhuOd4KjErXiamDmWwcVFHzaDZJ08E6hqhbpZN42Nhe4Ms1q+5FzjCjtNVIT\n"                                                           \
    "jdY5cCdSDWNjru9oeBmao7R2I1jhHrdi6awyeplLu1+0cp50HbYSaJeYS3pbssFE\n"                                                           \
    "EIWBhQKBgG3xleD4Sg9rG2OWQz5IrvLFg/Hy7YWyushVez61kZeLDnt9iM2um76k\n"                                                           \
    "/xFNIW0a+eL2VxRTCbXr9z86hjc/6CeSJHKYFQl4zsSAZkaIJ0+HbrhDNBAYh9b2\n"                                                           \
    "mRdX+OMdZ7Z5J3Glt8ENFRqe8RlESMpAKxjR+dID0bjwAjVr2KCh\n"                                                                       \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIIDQjCCAiqgAwIBAgIBBTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9waWNv\n"                                                           \
    "dGxzIHRlc3QgY2EwHhcNMjExMjEzMDY1MzQwWhcNMzExMjExMDY1MzQwWjAbMRkw\n"                                                           \
    "FwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"                                                           \
    "MIIBCgKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+\n"                                                           \
    "bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7Wc\n"                                                           \
    "NcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW\n"                                                           \
    "/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiN\n"                                                           \
    "kLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7\n"                                                           \
    "Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABo4GRMIGOMAkGA1UdEwQCMAAw\n"                                                           \
    "LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0G\n"                                                           \
    "A1UdDgQWBBQTW9cOMFPyPZ60/hut8dD0N4qemDAfBgNVHSMEGDAWgBS/ecqXsmB4\n"                                                           \
    "IJaqRlec36eyI/UlYzATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsF\n"                                                           \
    "AAOCAQEAYTglgIYqxhbmErQar8yFmRRJp93Zul+PnCuq1nkGPokJoytszoQtGBfw\n"                                                           \
    "ftgcMyTH3TOR22XThQafi/qWj3gz//oicZ09AuDfk/GMweWPjPGSs2lNUCbC9FqW\n"                                                           \
    "75JpYWsKqk8s0GwetZ710rX/65wJQAb4EcibMdWq98C/HUwQspXiXBXkEMDbMF5Q\n"                                                           \
    "s41vyeASk03jff+ofvTZl33sPurltO2oyRtDfUKWFAMBS7Bk/h/d3ZIwmv7DjXVw\n"                                                           \
    "ZKjxMZbXSmlgdngzBCBYZb5p+VkGXHqVjd07KhZd4nn5sqLy2i1COWB4OCb0xUHr\n"                                                           \
    "QxHvmJiqQ57FTFDypV0sKZRLuY9ovQ==\n"                                                                                           \
    "-----END CERTIFICATE-----\n"

int disable_debug = 0;
static const uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {0};
typedef uint8_t traffic_secrets_t[2 /* is_enc */][4 /* epoch */][PTLS_MAX_DIGEST_SIZE /* octets */];
#define TICKET_PATH "client_ticket.bin"
#define SDPTICKET_PATH "sdp_ticket.bin"
#define SDPDATA_FILEPATH "sdpdata.bin"
#define ECDSA_CERT_PATH "assets/ecdsa/cert.pem"
#define ECDSA_PKEY_PATH "assets/ecdsa/key.pem"

ptls_verify_certificate_t *verify_certificate;

void print_traffic_secrets(const traffic_secrets_t secrets) {
    for (int is_enc = 0; is_enc < 2; ++is_enc) {
        for (int epoch = 0; epoch < 4; ++epoch) {
            printf("is_enc=%d, epoch=%d:\n", is_enc, epoch);
            for (size_t i = 0; i < PTLS_MAX_DIGEST_SIZE; ++i) {
                printf("%02x ", secrets[is_enc][epoch][i]);
                if ((i + 1) % 8 == 0) {
                    printf("\n");
                }
            }
            printf("\n");
        }
    }
}

void print_base(uint8_t *base, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%.2x ", (int)base[i]);
        if (i % 4 == 3)
            printf(" ");
        if (i %16 == 15)
            printf("\n");
    }
    printf("\n");
}

void print_epochoffsets(size_t *epochoff) {
    for (int i = 0; i < 5; i++) {
        printf("epoch offset-%d: %d\t", i, epochoff[i]);
    }
    printf("\n");
}

static ptls_iovec_t saved_ticket = {NULL};

static int on_save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
//    saved_ticket.base = malloc(src.len);
//    memcpy(saved_ticket.base, src.base, src.len);
//    saved_ticket.len = src.len;

    printf(">>client save_ticket cb in client_handle_new_session_ticket()\n");
    printf("saved ticket:\n");
    print_base(src.base, src.len);
    /* write ticket to file: client_ticket.bin */
    FILE *fp = fopen(TICKET_PATH, "wb");
    assert(fp != NULL);
    size_t bytes_written = fwrite(src.base, sizeof(uint8_t), src.len, fp);
    assert(bytes_written == src.len);
    printf(">>client_ticket saved to client_ticket.bin\n");
    return 0;
}

static int on_copy_ticket(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    int ret;

    if ((ret = ptls_buffer_reserve(dst, src.len)) != 0)
        return ret;
    memcpy(dst->base + dst->off, src.base, src.len);
    dst->off += src.len;

    /* the session identifier seems to be generated by server in send_session_ticket(encode_session_identifier) */
    printf(">>server encrypted_ticket cb in \n-server handle hello(try_psk_handshake) or\n-server finish handshake(send_session_ticket):\n");
    printf("CH.psk.identities.lists[i]--identity(ptls_iovec_t):\n");
    print_base(src.base, src.len);

    return 0;
}

static int on_update_traffic_key(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret)
{
    traffic_secrets_t *secrets = *ptls_get_data_ptr(tls);
    assert(memcmp((*secrets)[is_enc][epoch], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    size_t size = ptls_get_cipher(tls)->hash->digest_size;
    memcpy((*secrets)[is_enc][epoch], secret, size);
    return 0;
}


static int feed_messages(ptls_t *tls, ptls_buffer_t *outbuf, size_t *out_epoch_offsets, const uint8_t *input,
                         const size_t *in_epoch_offsets, ptls_handshake_properties_t *props)
{
    size_t i;
    int ret = PTLS_ERROR_IN_PROGRESS;

    outbuf->off = 0;
    memset(out_epoch_offsets, 0, sizeof(*out_epoch_offsets) * 5);

    for (i = 0; i != 4; ++i) {
        size_t len = in_epoch_offsets[i + 1] - in_epoch_offsets[i];
        if (len != 0) {
            if (disable_debug) {
                printf("in_epoch_offsets[%d] - in_epoch_offsets[%d] = %d\n", i+1, i, len);
                printf("--in_epoch_offsets(sender):\n");
                print_epochoffsets(in_epoch_offsets);
                printf("++out_epoch_offsets(receiver):\n");
                print_epochoffsets(out_epoch_offsets);
                printf("Current in_epoch: %d\n", i);
                printf("input(%d): input(%d) + in_epoch_offsets(%d)\n", input+in_epoch_offsets[i], input, \
                in_epoch_offsets[i]);

            }
            ret = ptls_handle_message(tls, outbuf, out_epoch_offsets, i, input + in_epoch_offsets[i], len, props);
            if (disable_debug) {
                printf(">>>>Call ptls_handle_message\n");
                printf("--in_epoch_offsets(sender):\n");
                print_epochoffsets(in_epoch_offsets);
                printf("++out_epoch_offsets(receiver):\n");
                print_epochoffsets(out_epoch_offsets);
            }
            if (!(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
                break;
        }
    }

    return ret;
}

/* override self-signed certificate errors, for testing @xinshu */
static int verify_cert_cb(int ok, X509_STORE_CTX *ctx) {
    if (!ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
        printf("Verification error: %s\n", X509_verify_cert_error_string(err));

        // Example: Ignore a specific error (e.g., self-signed certificate)
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            printf("Ignoring self-signed certificate error\n");
            ok = 1; // Override error and continue verification
        }
    }
    return ok; // Return 1 to continue, 0 to abort verification
}


static X509 *x509_from_pem(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void *)pem, (int)strlen(pem));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert(cert != NULL && "failed to load certificate");
    BIO_free(bio);
    return cert;
}

static void setup_certificate(ptls_iovec_t *dst)
{
    FILE *fp;
    if ((fp = fopen(ECDSA_CERT_PATH, "rb")) == NULL) {
        fprintf(stderr, "Failed to open cert file at %s\n", ECDSA_CERT_PATH);
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);
    X509_free(cert);
}

static void setup_sign_certificate(ptls_openssl_sign_certificate_t *sc) {
    // load private key
    FILE *fp;
    if ((fp = fopen(ECDSA_PKEY_PATH, "rb")) == NULL) {
        fprintf(stderr, "Failed to open private key file at %s\n", ECDSA_PKEY_PATH);
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to load private key from file at %s\n", ECDSA_PKEY_PATH);
    }
    ptls_openssl_init_sign_certificate(sc, pkey);
    EVP_PKEY_free(pkey);
}

//static void setup_certificate(ptls_iovec_t *dst)
//{
//    X509 *cert = x509_from_pem(RSA_CERTIFICATE);
//
//    dst->base = NULL;
//    dst->len = i2d_X509(cert, &dst->base);
//
//    X509_free(cert);
//}
//
//static void setup_sign_certificate(ptls_openssl_sign_certificate_t *sc)
//{
//    BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, (int)strlen(RSA_PRIVATE_KEY));
//    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
//    assert(pkey != NULL || !"failed to load private key");
//    BIO_free(bio);
//
//    ptls_openssl_init_sign_certificate(sc, pkey);
//
//    EVP_PKEY_free(pkey);
//}

static ptls_key_exchange_context_t *key_from_pem(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void *)pem, (int)strlen(pem));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(pkey != NULL && "failed to load private key");
    BIO_free(bio);

    ptls_key_exchange_context_t *ctx;
    int ret = ptls_openssl_create_key_exchange(&ctx, pkey);
    assert(ret == 0 && "failed to setup private key");

    EVP_PKEY_free(pkey);
    return ctx;
}

static ptls_aead_context_t *create_ech_opener(ptls_ech_create_opener_t *self, ptls_hpke_kem_t **kem,
                                              ptls_hpke_cipher_suite_t **cipher, ptls_t *tls, uint8_t config_id,
                                              ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc, ptls_iovec_t info_prefix)
{
    static ptls_key_exchange_context_t *pem = NULL;
    if (pem == NULL) {
        pem = key_from_pem(ECH_PRIVATE_KEY);
        assert(pem != NULL);
    }

    *cipher = NULL;
    for (size_t i = 0; ptls_openssl_hpke_cipher_suites[i] != NULL; ++i) {
        if (ptls_openssl_hpke_cipher_suites[i]->id.kdf == cipher_id.kdf &&
            ptls_openssl_hpke_cipher_suites[i]->id.aead == cipher_id.aead) {
            *cipher = ptls_openssl_hpke_cipher_suites[i];
            break;
        }
    }
    if (*cipher == NULL)
        return NULL;

    ptls_aead_context_t *aead = NULL;
    ptls_buffer_t infobuf;
    int ret;

    ptls_buffer_init(&infobuf, "", 0);
    ptls_buffer_pushv(&infobuf, info_prefix.base, info_prefix.len);
    ptls_buffer_pushv(&infobuf, (const uint8_t *)ECH_CONFIG_LIST + 2,
                      sizeof(ECH_CONFIG_LIST) - 3); /* choose the only ECHConfig from the list */
    ret = ptls_hpke_setup_base_r(&ptls_openssl_hpke_kem_p256sha256, *cipher, pem, &aead, enc,
                                 ptls_iovec_init(infobuf.base, infobuf.off));

    Exit:
    ptls_buffer_dispose(&infobuf);
    return aead;
}



#endif //SDP_HANDSHAKE_TEST_PICOTLS_API_H
