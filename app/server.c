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

static int handle_connection(int sockfd, ptls_context_t *ctx, const char *server_name, const char *input_file,
                             ptls_handshake_properties_t *hsprop)
{
    static const int inputfd_is_benchmark = -2;

    ptls_t *tls = ptls_new(ctx, 1);
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
                        //                        ech_save_retry_configs();
                        /* release data sent as early-data, if server accepted it */
                        if (hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
                            shift_buffer(&ptbuf, early_bytes_sent);
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        if (ret == PTLS_ALERT_ECH_REQUIRED) {
                            assert(!ptls_is_server(tls));
                            //                            ech_save_retry_configs();
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
                            if (input_file != input_file_is_benchmark)
                                repeat_while_eintr(write(1, rbuf.base, rbuf.off), { goto Exit; });

                            if ((ret = ptls_buffer_reserve(&ptbuf, block_size)) != 0)
                                goto Exit;
                            /*check if it's early data*/
                            //                            if (memcmp(rbuf.base, req, rbuf.off) == 0) { /*receive early data*/
                            if (app_message_recv == 1) { /*reply to first app data*/
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

/* tls over tcp server */
int run_server(const char* host, const char* port, ptls_context_t *ctx, ptls_handshake_properties_t *server_hs_prop)
{
    struct sockaddr_storage sa;
    socklen_t salen;

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0)
        exit(1);

    int listen_fd, conn_fd, on = 1;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed");
        return 1;
    }
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return 1;
    }
    if (bind(listen_fd, (struct sockaddr *)&sa, salen) != 0) {
        perror("bind(2) failed");
        return 1;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        perror("listen(2) failed");
        return 1;
    }

    fprintf(stderr, "server started on port %d\n", ntohs(((struct sockaddr_in *)&sa)->sin_port));
    while (1) {
        fprintf(stderr, "waiting for connections\n");
        if ((conn_fd = accept(listen_fd, NULL, 0)) != -1)
            handle_connection(conn_fd, ctx, NULL, NULL, server_hs_prop);
    }
}


static void server_usage(const char *cmd) {
    printf("Server Usage: %s [options] host port protocol\n"
           "\n"
           "host:                IP address of server\n"
           "port:                port number of server\n"
           "test sig-name:       dilithium3, dilithium2, dilithium5, rsa, ecdsa\n" // this decides which server cert to load
           "Options:\n"
           "-p                   load post-quantum certificates\n"
           "-m                   require mutual authentication\n"
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
        server_usage(argv[0]);
        goto Exit;
    }

    int ch, message_size, is_oqs_sig, is_mutual_auth;
    while ((ch = getopt(argc, argv, "n:pmh")) != -1) {
        switch (ch) {
        case 'p':
            is_oqs_sig = 1;
            printf("setting: load post-quantum signature algorithm\n");
            break;
        case 'm':
            is_mutual_auth = 1;
            printf("setting: mutual authentication mode\n");
            break;
        case 'h':
            server_usage(argv[0]);
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

    /* for simplicity, client and server share the same pair of cert&pkey */
    if (!is_oqs_sig)
    {
        /* traditional signature algos */
        printf("is_oqs_sig = %d", is_oqs_sig);
        sprintf(certpath, "%s%s%s%s", certsdir, sig_name, sep, "cert.pem");
        sprintf(privkeypath, "%s%s%s%s", certsdir, sig_name, sep, "key.pem");
        sprintf(capath, "%s%s%s%s", certsdir, "ca", sep, "test-ca.crt");
    }
    else
    {
        printf("is_oqs_sig = %d", is_oqs_sig);
        /* post quantum signature algos */
        sprintf(certpath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.crt");
        sprintf(privkeypath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.key");
        sprintf(capath, "%s%s%s%s", certsdir, "oqs-ca", sep, "dilithium3_CA.crt");
    }
    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;
    ptls_iovec_t cert;

    setup_certificate(&cert, certpath);
    setup_private_key(&openssl_sign_certificate, privkeypath, sig_name, is_oqs_sig);

    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges, /*ptls_openssl_key_exchanges by default*/
                          .cipher_suites = ptls_openssl_cipher_suites_all, /*ptls_openssl_cipher_suites_all by default*/
                          .certificates = {&cert, 1},
                          .ech = {.client = {NULL}, .server = {NULL}}, /* ech is disabled */
                          .sign_certificate = &openssl_sign_certificate.super,
                          .verify_certificate = &openssl_verify_certificate.super};
    ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};

    if (is_mutual_auth)
    {
        ctx.require_client_authentication = 1;
        /* setup ca cert file for client's certificate verification */
        ptls_openssl_init_verify_certificate(&openssl_verify_certificate, init_cert_store(capath));
    }

    /* todo: setup log @xinshu*/

    /* run server */
    return run_server(host, port, &ctx, &server_hs_prop);

Exit:
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(oqsprovider);
#endif
    exit(1);
}