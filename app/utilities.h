//
// Created by xinshu on 02/01/25.
//

#ifndef HSIG_PICOTLS_UTILITIES_H
#define HSIG_PICOTLS_UTILITIES_H
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <openssl/pem.h>
#include "picotls/openssl.h"

#define TICKET_PATH "client_ticket.bin" /* not using it */

int family = AF_INET;

enum Sig_schemes {
    SIG_DILITHIUM2,
    SIG_DILITHIUM3,
    SIG_DILITHIUM5,
    SIG_RSA,
    SIG_ECDSA,
    SIG_SCHEMES_COUNT
};

static const char *sig_names[] __attribute__((unused)) = {
    [SIG_DILITHIUM2] = "dilithium2",
    [SIG_DILITHIUM3] = "dilithium3",
    [SIG_DILITHIUM5] = "dilithium5",
    [SIG_RSA] = "rsa",
    [SIG_ECDSA] = "ecdsa",
};

_Static_assert(SIG_SCHEMES_COUNT ==
                   sizeof(sig_names) / sizeof(sig_names[0]),
               "sig_names[] and Sig_schemes enum must match");

static int get_signame(char const *sig_name) {
    for (int i = 0; i < SIG_SCHEMES_COUNT; i++) {
        if (strcmp(sig_name, sig_names[i]) == 0) return i;
    }
    return -1;
}

static void wrong_signame() {
    fprintf(stderr, "Unsupported signature scheme! (Choose from ");
    for (int i = 0; i < SIG_SCHEMES_COUNT; i++) {
        fprintf(stderr, "%s", sig_names[i]);
        if (i != SIG_SCHEMES_COUNT - 1) fprintf(stderr, ", ");
    }
    fprintf(stderr, ")\n");
}

static void setup_certificate(ptls_iovec_t *dst, const char *fn)
{
    FILE *fp;
    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "Failed to open cert file at %s\n", fn);
        exit(1);
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);
}

static inline void setup_private_key(ptls_openssl_sign_certificate_t *sc, const char *fn, const char *sig_name, int is_oqs_sig)
{
    FILE *fp;
    EVP_PKEY *pkey;

    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL) {
        fprintf(stderr, "failed to read private key from file:%s\n", fn);
        exit(1);
    }

    if (is_oqs_sig)
        ptls_openssl_init_oqs_sign_certificate(sc, pkey, sig_name);
    else
        ptls_openssl_init_trad_sign_certificate(sc, pkey);
    EVP_PKEY_free(pkey);
}

static inline X509_STORE *init_cert_store(char const *crt_file)
{
    int ret = 0;
    X509_STORE *store = X509_STORE_new();

    if (store != NULL) {
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        ret = X509_LOOKUP_load_file(lookup, crt_file, X509_FILETYPE_PEM);
        if (ret != 1) {
            fprintf(stderr, "Cannot load store (%s), ret = %d\n", crt_file, ret);
            X509_STORE_free(store);
            exit(1);
        }
    } else {
        fprintf(stderr, "Cannot get a new X509 store\n");
        exit(1);
    }
    printf("[%s]: using costomised cert store: %s, %d\n", __func__, crt_file, __LINE__);

    return store;
}

static int load_session_ticket(ptls_iovec_t *ticket, const char *ticket_path) {
    int ret = 0;
    /* load ticket from file*/
    FILE *fp = fopen(ticket_path, "rb");
    assert(fp != NULL);
    fseek(fp, 0, SEEK_END);
    size_t fplen = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    ticket->base = malloc(fplen);
    assert(ticket->base != NULL);
    size_t bytes_read = fread(ticket->base, sizeof(uint8_t), fplen, fp);
    assert(bytes_read == fplen);
    ticket->len = fplen;
    fclose(fp);

    return ret;
}

static int on_save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
    /* write ticket to file: client_ticket.bin */
    FILE *fp = fopen(TICKET_PATH, "wb");
    assert(fp != NULL);
    size_t bytes_written = fwrite(src.base, sizeof(uint8_t), src.len, fp);
    assert(bytes_written == src.len);
    fclose(fp);
    printf(">>client_ticket saved to client_ticket.bin\n");
    return 0;
}

static inline int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port,
                                  int family, int type, int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;

    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "Failed to resolve address '%s:%s': %s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL\n");
        return -1;
    }
    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

#define repeat_while_eintr(expr, exit_block)                                                                                       \
    while ((expr) < 0) {                                                                                                           \
        if (errno == EINTR)                                                                                                        \
            continue;                                                                                                              \
        exit_block;                                                                                                                \
    }

static void shift_buffer(ptls_buffer_t *buf, size_t delta)
{
    if (delta != 0) {
        assert(delta <= buf->off);
        if (delta != buf->off)
            memmove(buf->base, buf->base + delta, buf->off - delta);
        buf->off -= delta;
    }
}

/* sentinels indicating that the endpoint is in benchmark mode */
static const char input_file_is_benchmark[] = "is:benchmark";

//static void ech_save_retry_configs(void)
//{
//    if (ech.retry.configs.base == NULL)
//        return;
//
//    FILE *fp;
//    if ((fp = fopen(ech.retry.fn, "wt")) == NULL) {
//        fprintf(stderr, "failed to write to ECH config file:%s:%s\n", ech.retry.fn, strerror(errno));
//        exit(1);
//    }
//    fwrite(ech.retry.configs.base, 1, ech.retry.configs.len, fp);
//    fclose(fp);
//}



#endif // HSIG_PICOTLS_UTILITIES_H
