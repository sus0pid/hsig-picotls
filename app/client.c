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

unsigned use_early_data = 0;
unsigned update_session_ticket = 0;
unsigned use_dhe_on_psk = 0;
unsigned enable_session_ticket_resumption = 0;
char *input_file = NULL;
unsigned enable_bench_setting = 0;


/* we test full handshake--tls-tcp */
static int run_client(const char* host, const char *port, ptls_context_t *ctx,
                          ptls_handshake_properties_t *client_hs_prop, const char *server_name
                          int keep_sender_open, int message_size, double *cnt_time_cost, double *early_time_cost)
{
    int inputfd = 0, ret = 0, is_shutdown = 0, num_msg_sent = 0;
    size_t early_bytes_sent = 0;
    uint64_t data_received = 0;
    ssize_t ioret;
    struct timespec event_start, event_end, cnt_start;
//    const char *req[8192] = {0};
//    memset(req, 'A', message_size);
    const char *req = "GET / HTTP/1.0\r\n\r\n"; /*early data*/
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n"; /*reply to early data*/
    const char *sd_signal = "shutdown";
    enum { IN_HANDSHAKE, IN_1RTT, IN_SHUTDOWN } state = IN_HANDSHAKE;
    static const int inputfd_is_benchmark = -2;
    static const size_t block_size = 16384;


    /*setup handshake parameters, we omit this step as full handshake does not need it*/
    static size_t max_early_data_size = 0;
    ptls_iovec_t saved_ticket;
    ptls_encrypt_ticket_t save_ticket = {on_save_ticket};
    if (enable_session_ticket_resumption) {
        saved_ticket = ptls_iovec_init(NULL, 0);
        load_session_ticket(&saved_ticket, TICKET_PATH); /*load session ticket*/
        client_hs_prop->client.session_ticket = saved_ticket;
    }
    if (use_early_data)
        client_hs_prop->client.max_early_data_size = &max_early_data_size;
    if (!update_session_ticket)
        ctx->save_ticket = NULL; /* don't allow further test to update the saved ticket */
    else
        ctx->save_ticket = &save_ticket;
    if (use_dhe_on_psk)
        ctx->require_dhe_on_psk = 1; /*enable dhe on 0-rtt*/

    ptls_t *client = ptls_new(ctx, 0);
    ptls_buffer_t rbuf, encbuf, ptbuf;
    ptls_buffer_init(&rbuf, "", 0);
    ptls_buffer_init(&encbuf, "", 0);
    ptls_buffer_init(&ptbuf, "", 0);


    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t salen;

    if (resolve_address((struct sockaddr *) &server_addr, &salen, host, port, family, SOCK_STREAM,
                        IPPROTO_TCP) != 0)
        exit(1);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(1);
    }

    if (connect(sockfd, &server_addr, salen) != 0) {
        perror("socket connect failed");
        exit(1);
    }

    uint64_t start_at = ctx->get_time->cb(ctx->get_time);

    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (input_file == input_file_is_benchmark) {
        if (!ptls_is_server(client))
            inputfd = inputfd_is_benchmark;
    } else if (input_file != NULL) {
        if ((inputfd = open(input_file, O_RDONLY)) == -1) {
            fprintf(stderr, "failed to open file:%s:%s\n", input_file, strerror(errno));
            ret = 1;
            goto Exit;
        }
    }

    /* client send client hello */
    if (server_name != NULL)
    {
        ptls_set_server_name(client, server_name, 0);
        clock_gettime(CLOCK_REALTIME, &cnt_start); /*timestamp of handle 0-rtt reply back*/
        if ((ret = ptls_handshake(client, &encbuf, NULL, NULL, client_hs_prop)) != PTLS_ERROR_IN_PROGRESS) {
            fprintf(stderr, "ptls_handshake:%d\n", ret);
            ret = 1;
            goto Exit;
        }
        /* client send early data */
        if (use_early_data) {
            clock_gettime(CLOCK_REALTIME, &event_start);
            ret = ptls_send(client, &encbuf, req, strlen(req));
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
                    if ((ret = ptls_handshake(client, &encbuf, bytebuf + off, &leftlen, client_hs_prop)) == 0) {
                        state = IN_1RTT;
                        assert(ptls_is_server(client) || client_hs_prop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
//                        ech_save_retry_configs();
                        /* release data sent as early-data, if server accepted it */
                        if (client_hs_prop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
                            shift_buffer(&ptbuf, early_bytes_sent);
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        if (ret == PTLS_ALERT_ECH_REQUIRED) {
                            assert(!ptls_is_server(client));
//                            ech_save_retry_configs();
                        }
                        if (encbuf.off != 0)
                            repeat_while_eintr(write(sockfd, encbuf.base, encbuf.off), { break; });
                        fprintf(stderr, "ptls_handshake:%d\n", ret);
                        goto Exit;
                    }
                } else {
                    if ((ret = ptls_receive(client, &rbuf, bytebuf + off, &leftlen)) == 0) {
                        if (rbuf.off != 0) {
                            data_received += rbuf.off;
                            if (input_file != input_file_is_benchmark)
                                repeat_while_eintr(write(1, rbuf.base, rbuf.off), { goto Exit; });

                            /*check if it is first app data reply*/
                            if (memcmp(rbuf.base, resp, rbuf.off) == 0) {
                                clock_gettime(CLOCK_REALTIME, &event_end); /*timestamp of handle 0-rtt reply back*/
                                printf("\n\n-----------------Time measurement retults-----------------\n");
                                if (use_early_data) {
                                    *early_time_cost = (event_end.tv_sec - event_start.tv_sec) * 1000000.0 +
                                                       (event_end.tv_nsec - event_start.tv_nsec) / 1000.0;
                                    printf("early message time elapsed: %lf us\n", *early_time_cost);

                                }
                                *cnt_time_cost = (event_end.tv_sec - cnt_start.tv_sec) * 1000000.0 +
                                                 (event_end.tv_nsec - cnt_start.tv_nsec) / 1000.0;
                                printf("connection establish time elapsed: %lf us\n", *cnt_time_cost);
                                printf("--------------------Time measurement retults end-----------------\n\n");

                                /* send 'shutdown' message to server*/
                                if (enable_bench_setting)
                                {
//                                    if ((ret = ptls_buffer_reserve(&ptbuf, block_size)) != 0)
//                                        goto Exit;
//                                    memcpy(ptbuf.base, sd_signal, strlen(sd_signal));
//                                    ptbuf.off = strlen(sd_signal);
                                    is_shutdown = 1;
                                }

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
            /* send first app message */
            if (enable_bench_setting && (!use_early_data) && (!num_msg_sent)) {
                if ((ret = ptls_buffer_reserve(&ptbuf, block_size)) != 0)
                    goto Exit;
                memcpy(ptbuf.base, req, message_size);
                ptbuf.off = message_size;
                ++num_msg_sent;
            } else {
                if (!enable_bench_setting && inputfd >= 0 && (FD_ISSET(inputfd, &readfds) || FD_ISSET(inputfd, &exceptfds))) {
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
                } else if (!enable_bench_setting && inputfd == inputfd_is_benchmark) {
                    if (ptbuf.capacity < block_size) {
                        if ((ret = ptls_buffer_reserve(&ptbuf, block_size - ptbuf.capacity)) != 0)
                            goto Exit;
                        memset(ptbuf.base + ptbuf.capacity, 0, block_size - ptbuf.capacity);
                    }
                    ptbuf.off = block_size;
                }
            }
        }

        if (ptbuf.off != 0) {
            if (state == IN_HANDSHAKE) {
                size_t send_amount = 0;
                if (server_name != NULL && client_hs_prop->client.max_early_data_size != NULL) {
                    size_t max_can_be_sent = *client_hs_prop->client.max_early_data_size;
                    if (max_can_be_sent > ptbuf.off)
                        max_can_be_sent = ptbuf.off;
                    send_amount = max_can_be_sent - early_bytes_sent;
                }
                if (send_amount != 0) {
                    if ((ret = ptls_send(client, &encbuf, ptbuf.base, send_amount)) != 0) {
                        fprintf(stderr, "ptls_send(early_data):%d\n", ret);
                        goto Exit;
                    }
                    early_bytes_sent += send_amount;
                }
            } else {
                if ((ret = ptls_send(client, &encbuf, ptbuf.base, ptbuf.off)) != 0) {
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

        /* close the client after getting the first application messge from server @xinshu*/
        if (state == IN_1RTT && is_shutdown)
        {
            ptls_buffer_t wbuf;
            uint8_t wbuf_small[32];
            ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
            if ((ret = ptls_send_alert(client, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0) {
                fprintf(stderr, "ptls_send_alert:%d\n", ret);
            }
            if (wbuf.off != 0)
                repeat_while_eintr(write(sockfd, wbuf.base, wbuf.off), {
                    ptls_buffer_dispose(&wbuf);
                    goto Exit;
                });
            ptls_buffer_dispose(&wbuf);
            shutdown(sockfd, SHUT_WR);
            printf("[%s]: client sends shutdown tls signal\n", __func__);
            state = IN_SHUTDOWN;
        }


        /* close the sender side after sending input_file contents */
        if (state == IN_1RTT && inputfd == -1) {
            if (!keep_sender_open) {
                ptls_buffer_t wbuf;
                uint8_t wbuf_small[32];
                ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
                if ((ret = ptls_send_alert(client, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0) {
                    fprintf(stderr, "ptls_send_alert:%d\n", ret);
                }
                if (wbuf.off != 0)
                    repeat_while_eintr(write(sockfd, wbuf.base, wbuf.off), {
                        ptls_buffer_dispose(&wbuf);
                        goto Exit;
                    });
                ptls_buffer_dispose(&wbuf);
                shutdown(sockfd, SHUT_WR);
                printf("[%s]: client sends shutdown tls signal\n", __func__);
            }
            state = IN_SHUTDOWN;
        }
    }

Exit:
    if (input_file == input_file_is_benchmark) {
        double elapsed = (ctx->get_time->cb(ctx->get_time) - start_at) / 1000.0;
        ptls_cipher_suite_t *cipher_suite = ptls_get_cipher(client);
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
    ptls_free(client);
    return ret;
}



static void client_usage(const char *cmd) {
    printf("Client Usage: %s [options] host port protocol\n"
           "\n"
           "host:                IP address of server\n"
           "port:                port number of server\n"
           "test sig-name:       dilithium3, dilithium2, dilithium5, rsa, ecdsa\n" // this decides which server cert to load
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

    int ch, message_size, is_oqs_sig = 0, is_mutual_auth = 0;
    while ((ch = getopt(argc, argv, "mn:h")) != -1) {
        switch (ch) {
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

    if (sig_index > 2)
    {
        /* traditional signature algos */
        sprintf(certpath, "%s%s%s%s", certsdir, sig_name, sep, "cert.pem");
        sprintf(privkeypath, "%s%s%s%s", certsdir, sig_name, sep, "key.pem");
    } else
    {
        is_oqs_sig = 1;
        /* post quantum signature algos */
        sprintf(certpath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.crt");
        sprintf(privkeypath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.key");
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
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, NULL);

    /* CN in certificate
     * rsa: rsa.test.example.com
     * ed25519: ed25519.test.example.com
     * others: test.example.com*/
    const char *server_name = (strcmp(sig_name, "rsa") == 0) ? "rsa.test.example.com" : "test.example.com";

    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges, /*ptls_openssl_key_exchanges by default*/
                          .cipher_suites = ptls_openssl_cipher_suites_all, /*ptls_openssl_cipher_suites_all by default*/
                          .certificates = {&cert, 1},
                          .ech = {.client = {NULL}, .server = {NULL}}, /* ech is disabled */
                          .sign_certificate = &openssl_sign_certificate.super,
                          .verify_certificate = &openssl_verify_certificate.super,
                          .require_oqssig_on_auth = is_oqs_sig /* oqs auth enabled */
    };
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}}}};

    /* setup log*/

    /* run client TODO: set the arguments*/
    double a, b;
    return run_client(host, port, &ctx, &client_hs_prop, server_name, 0, 0, &a, &b);


Exit:
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(oqsprovider);
#endif
    exit(1);
}
