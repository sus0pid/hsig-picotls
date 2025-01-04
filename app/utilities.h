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

int family = AF_INET;

enum Sig_schemes {
    DILITHIUM2,
    DILITHIUM3,
    DILITHIUM5,
    RSA,
    ECDSA,
    SIG_SCHEMES_COUNT
};

static const char *sig_names[] __attribute__((unused)) = {
    [DILITHIUM2] = "dilithium2",
    [DILITHIUM3] = "dilithium3",
    [DILITHIUM5] = "dilithium5",
    [RSA] = "rsa",
    [ECDSA] = "ecdsa",
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

/* sentinels indicating that the endpoint is in benchmark mode */
static const char input_file_is_benchmark[] = "is:benchmark";

static void ech_save_retry_configs(void)
{
    if (ech.retry.configs.base == NULL)
        return;

    FILE *fp;
    if ((fp = fopen(ech.retry.fn, "wt")) == NULL) {
        fprintf(stderr, "failed to write to ECH config file:%s:%s\n", ech.retry.fn, strerror(errno));
        exit(1);
    }
    fwrite(ech.retry.configs.base, 1, ech.retry.configs.len, fp);
    fclose(fp);
}

static int handle_connection(int sockfd, ptls_context_t *ctx, const char *server_name, const char *input_file,
                             ptls_handshake_properties_t *hsprop, int request_key_update, int keep_sender_open,
                             int enable_bench)
{
    static const int inputfd_is_benchmark = -2;

    ptls_t *tls = ptls_new(ctx, server_name == NULL);
    ptls_buffer_t rbuf, encbuf, ptbuf;
    enum { IN_HANDSHAKE, IN_1RTT, IN_SHUTDOWN } state = IN_HANDSHAKE;
    int inputfd = 0, ret = 0, app_message_recv = 0;
    size_t early_bytes_sent = 0;
    uint64_t data_received = 0;
    ssize_t ioret;
    struct timespec event_start, event_end;
    const char *req = "GET / HTTP/1.0\r\n\r\n"; /*early data*/
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n"; /*reply to early data*/
    static const size_t block_size = 16384;

    uint64_t start_at = ctx->get_time->cb(ctx->get_time);

    ptls_buffer_init(&rbuf, "", 0);
    ptls_buffer_init(&encbuf, "", 0);
    ptls_buffer_init(&ptbuf, "", 0);

    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (input_file == input_file_is_benchmark) {
        if (!ptls_is_server(tls))
            inputfd = inputfd_is_benchmark;
    } else if (input_file != NULL) {
        if ((inputfd = open(input_file, O_RDONLY)) == -1) {
            fprintf(stderr, "failed to open file:%s:%s\n", input_file, strerror(errno));
            ret = 1;
            goto Exit;
        }
    }

    if (server_name != NULL) {
        ptls_set_server_name(tls, server_name, 0);
        if ((ret = ptls_handshake(tls, &encbuf, NULL, NULL, hsprop)) != PTLS_ERROR_IN_PROGRESS) {
            fprintf(stderr, "ptls_handshake:%d\n", ret);
            ret = 1;
            goto Exit;
        }
        if (hsprop->client.session_ticket.base != NULL) {
            clock_gettime(CLOCK_REALTIME, &event_start);
            ret = ptls_send(tls, &encbuf, req, strlen(req));
            assert(ret == 0);
        }
    }

    while (1) {
        /* check if data is available */
        fd_set readfds, writefds, exceptfds;
        int maxfd = 0;
        struct timeval timeout;
        do {
            FD_ZERO(&readfds);
            FD_ZERO(&writefds);
            FD_ZERO(&exceptfds);
            FD_SET(sockfd, &readfds);
            if (encbuf.off != 0 || inputfd == inputfd_is_benchmark)
                FD_SET(sockfd, &writefds);
            FD_SET(sockfd, &exceptfds);
            maxfd = sockfd + 1;
            if (inputfd >= 0) {
                FD_SET(inputfd, &readfds);
                FD_SET(inputfd, &exceptfds);
                if (maxfd <= inputfd)
                    maxfd = inputfd + 1;
            }
            timeout.tv_sec = encbuf.off != 0 ? 0 : 3600;
            timeout.tv_usec = 0;
        } while (select(maxfd, &readfds, &writefds, &exceptfds, &timeout) == -1);

        /* consume incoming messages */
        if (FD_ISSET(sockfd, &readfds) || FD_ISSET(sockfd, &exceptfds)) {
            char bytebuf[16384];
            size_t off = 0, leftlen;
            while ((ioret = read(sockfd, bytebuf, sizeof(bytebuf))) == -1 && errno == EINTR)
                ;
            if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                /* no data */
                ioret = 0;
            } else if (ioret <= 0) {
                goto Exit;
            }
            while ((leftlen = ioret - off) != 0) {
                if (state == IN_HANDSHAKE) {
                    if ((ret = ptls_handshake(tls, &encbuf, bytebuf + off, &leftlen, hsprop)) == 0) {
                        state = IN_1RTT;
                        assert(ptls_is_server(tls) || hsprop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
                        ech_save_retry_configs();
                        /* release data sent as early-data, if server accepted it */
                        if (hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
                            shift_buffer(&ptbuf, early_bytes_sent);
                        if (request_key_update)
                            ptls_update_key(tls, 1);
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        if (ret == PTLS_ALERT_ECH_REQUIRED) {
                            assert(!ptls_is_server(tls));
                            ech_save_retry_configs();
                        }
                        if (encbuf.off != 0)
                            repeat_while_eintr(write(sockfd, encbuf.base, encbuf.off), { break; });
                        fprintf(stderr, "ptls_handshake:%d\n", ret);
                        goto Exit;
                    }
                } else {
                    if ((ret = ptls_receive(tls, &rbuf, bytebuf + off, &leftlen)) == 0) {
                        if (rbuf.off != 0) {
                            ++app_message_recv;
                            data_received += rbuf.off;
                            if (input_file != input_file_is_benchmark && !enable_bench)
                                repeat_while_eintr(write(1, rbuf.base, rbuf.off), { goto Exit; });

                            if ((ret = ptls_buffer_reserve(&ptbuf, block_size)) != 0)
                                goto Exit;
                            /*check if it's early data*/
                            //                            if (memcmp(rbuf.base, req, rbuf.off) == 0) { /*receive early data*/
                            if (enable_bench && (app_message_recv == 1)) { /*reply to first app data*/
                                memcpy(ptbuf.base, resp, strlen(resp));
                                ptbuf.off = strlen(resp);
                            } else { /* echo back to client */
                                memcpy(ptbuf.base, rbuf.base, rbuf.off);
                                ptbuf.off = rbuf.off;
                            }
                            rbuf.off = 0;
                        }
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        fprintf(stderr, "ptls_receive:%d\n", ret);
                        goto Exit;
                    }
                }
                off += leftlen;
            }
        }

        /* encrypt data to send, if any is available */
        if (encbuf.off == 0 || state == IN_HANDSHAKE) {
            if (inputfd >= 0 && (FD_ISSET(inputfd, &readfds) || FD_ISSET(inputfd, &exceptfds))) {
                if ((ret = ptls_buffer_reserve(&ptbuf, block_size)) != 0)
                    goto Exit;
                while ((ioret = read(inputfd, ptbuf.base + ptbuf.off, block_size)) == -1 && errno == EINTR)
                    ;
                if (ioret > 0) {
                    ptbuf.off += ioret;
                } else if (ioret == 0) {
                    /* closed */
                    if (input_file != NULL)
                        close(inputfd);
                    inputfd = -1;
                }
            } else if (inputfd == inputfd_is_benchmark) {
                if (ptbuf.capacity < block_size) {
                    if ((ret = ptls_buffer_reserve(&ptbuf, block_size - ptbuf.capacity)) != 0)
                        goto Exit;
                    memset(ptbuf.base + ptbuf.capacity, 0, block_size - ptbuf.capacity);
                }
                ptbuf.off = block_size;
            }
        }

        if (ptbuf.off != 0) {
            if (state == IN_HANDSHAKE) {
                size_t send_amount = 0;
                if (server_name != NULL && hsprop->client.max_early_data_size != NULL) {
                    size_t max_can_be_sent = *hsprop->client.max_early_data_size;
                    if (max_can_be_sent > ptbuf.off)
                        max_can_be_sent = ptbuf.off;
                    send_amount = max_can_be_sent - early_bytes_sent;
                }
                if (send_amount != 0) {
                    if ((ret = ptls_send(tls, &encbuf, ptbuf.base, send_amount)) != 0) {
                        fprintf(stderr, "ptls_send(early_data):%d\n", ret);
                        goto Exit;
                    }
                    early_bytes_sent += send_amount;
                }
            } else {
                if ((ret = ptls_send(tls, &encbuf, ptbuf.base, ptbuf.off)) != 0) {
                    fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
                    goto Exit;
                }
                ptbuf.off = 0;
            }
        }

        /* send any data */
        if (encbuf.off != 0) {
            while ((ioret = write(sockfd, encbuf.base, encbuf.off)) == -1 && errno == EINTR)
                ;
            if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                /* no data */
            } else if (ioret <= 0) {
                goto Exit;
            } else {
                shift_buffer(&encbuf, ioret);
            }
        }

        /* close the sender side when necessary */
        if (state == IN_1RTT && inputfd == -1) {
            if (!keep_sender_open) {
                ptls_buffer_t wbuf;
                uint8_t wbuf_small[32];
                ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
                if ((ret = ptls_send_alert(tls, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0) {
                    fprintf(stderr, "ptls_send_alert:%d\n", ret);
                }
                if (wbuf.off != 0)
                    repeat_while_eintr(write(sockfd, wbuf.base, wbuf.off), {
                        ptls_buffer_dispose(&wbuf);
                        goto Exit;
                    });
                ptls_buffer_dispose(&wbuf);
                shutdown(sockfd, SHUT_WR);
            }
            state = IN_SHUTDOWN;
        }
    }

Exit:
    if (input_file == input_file_is_benchmark) {
        double elapsed = (ctx->get_time->cb(ctx->get_time) - start_at) / 1000.0;
        ptls_cipher_suite_t *cipher_suite = ptls_get_cipher(tls);
        fprintf(stderr, "received %" PRIu64 " bytes in %.3f seconds (%f.3Mbps); %s\n", data_received, elapsed,
                data_received * 8 / elapsed / 1000 / 1000, cipher_suite != NULL ? cipher_suite->aead->name : "unknown cipher");
    }

    if (sockfd != -1)
        close(sockfd);
    if (input_file != NULL && input_file != input_file_is_benchmark && inputfd >= 0)
        close(inputfd);
    ptls_buffer_dispose(&rbuf);
    ptls_buffer_dispose(&encbuf);
    ptls_buffer_dispose(&ptbuf);
    ptls_free(tls);

    return ret != 0;
}

#endif // HSIG_PICOTLS_UTILITIES_H
