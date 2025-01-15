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
#include "bench_common.h"

unsigned use_early_data = 0;
unsigned update_session_ticket = 0;
unsigned use_dhe_on_psk = 0;
unsigned enable_session_ticket_resumption = 0;
char *input_file = NULL;
unsigned enable_bench_setting = 0;

static int run_one_client(const char* host, const char *port, ptls_context_t *ctx, const char *server_name,
                          const char *input_file, ptls_handshake_properties_t *client_hsprop)
{
    uint64_t t_hs_start, t_appmsg_received;
    uint64_t t_client_hs;
    static const int inputfd_is_benchmark = -2;
    enum { IN_HANDSHAKE, IN_1RTT, IN_SHUTDOWN } state = IN_HANDSHAKE;
    int inputfd = 0, ret = 0;
    ssize_t ioret;
    size_t early_bytes_sent = 0;
    const char *hello_msg = "hello world\n";
    const size_t hello_msg_len = strlen(hello_msg);
    /* configure ptls client */
    ctx->save_ticket = NULL; /* don't allow further connections to update the saved ticket */
    ptls_t *client = ptls_new(ctx, 0);
    ptls_buffer_t rbuf, encbuf, ptbuf;
    ptls_buffer_init(&rbuf, "", 0);
    ptls_buffer_init(&encbuf, "", 0);
    ptls_buffer_init(&ptbuf, "", 0);

    /* create a tcp connection */
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t salen;
    if (resolve_address((struct sockaddr *) &server_addr, &salen, host, port, family, SOCK_STREAM,
                        IPPROTO_TCP) != 0)
        goto Exit;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        goto Exit;
    }
    if (connect(sockfd, &server_addr, salen) != 0) {
        perror("socket connect failed");
        goto Exit;
    }

    // Set the socket to non-blocking mode
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
        perror("failed to set non-blocking mode");
        goto Exit;
    }

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

    ptls_set_server_name(client, server_name, 0);
    t_hs_start = bench_time();
    if ((ret = ptls_handshake(client, &encbuf, NULL, NULL, client_hsprop)) != PTLS_ERROR_IN_PROGRESS) {
        fprintf(stderr, "ptls_handshake:%d\n", ret);
        ret = 1;
        goto Exit;
    }
    printf(">> client sent ClientHello, line%d\n", __LINE__);

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
                    if ((ret = ptls_handshake(client, &encbuf, bytebuf + off, &leftlen, client_hsprop)) == 0) {
                        state = IN_1RTT;
                        assert(ptls_is_server(client) || client_hsprop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
                        /* release data sent as early-data, if server accepted it */
                        if (client_hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
                            shift_buffer(&ptbuf, early_bytes_sent);
                    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
                        /* ok */
                    } else {
                        if (ret == PTLS_ALERT_ECH_REQUIRED) {
                            assert(!ptls_is_server(client));
                        }
                        if (encbuf.off != 0)
                            repeat_while_eintr(write(sockfd, encbuf.base, encbuf.off), { break; });
                        fprintf(stderr, "ptls_handshake:%d\n", ret);
                        goto Exit;
                    }
                } else {
                    if ((ret = ptls_receive(client, &rbuf, bytebuf + off, &leftlen)) == 0) {
                        if (rbuf.off != 0) {
                            printf("Client received message: %.*s\n", (int)rbuf.off, rbuf.base);

                            // Check if the received message is "hello world\n"
                            if (rbuf.off == hello_msg_len && memcmp(rbuf.base, hello_msg, hello_msg_len) == 0) {
                                t_appmsg_received = bench_time();
                                printf("Hello message received, shutting down connection.\n");
                                t_client_hs = t_appmsg_received - t_hs_start;
                                printf("Time cost: %.2f us\n", t_client_hs);

                                // Send a close notify alert to the server
                                ptls_buffer_t wbuf;
                                uint8_t wbuf_small[32];
                                ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
                                if ((ret = ptls_send_alert(client, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0) {
                                    fprintf(stderr, "Failed to send close notify alert: %d\n", ret);
                                }
                                if (wbuf.off != 0)
                                    repeat_while_eintr(write(sockfd, wbuf.base, wbuf.off), { break; });
                                ptls_buffer_dispose(&wbuf);

                                // Shutdown the connection
                                shutdown(sockfd, SHUT_WR);
                                state = IN_SHUTDOWN;
                                break; // Exit the loop
                            }

                            if (input_file != input_file_is_benchmark)
                                repeat_while_eintr(write(1, rbuf.base, rbuf.off), { goto Exit; });
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
            static const size_t block_size = 16384;
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
                if (server_name != NULL && client_hsprop->client.max_early_data_size != NULL) {
                    size_t max_can_be_sent = *client_hsprop->client.max_early_data_size;
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
    }

Exit:
    if (sockfd != -1)
        close(sockfd);
    if (input_file != NULL && input_file != input_file_is_benchmark && inputfd >= 0)
        close(inputfd);
    ptls_buffer_dispose(&rbuf);
    ptls_buffer_dispose(&encbuf);
    ptls_buffer_dispose(&ptbuf);
    ptls_free(client);

    return ret != 0;
}


static void client_usage(const char *cmd) {
    printf("Client Usage: %s [options] host port protocol\n"
           "\n"
           "dst host:                IP address of server\n"
           "dst port:                port number of server\n"
           "load cert&key:           dilithium3, dilithium2, dilithium5, rsa, ecdsa\n" // this decides which server cert to load
           "Options:\n"
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

    int ch, message_size, is_oqs_auth = 0, is_hsig_auth;
    while ((ch = getopt(argc, argv, "n:h")) != -1) {
        switch (ch) {
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

    if (sig_index > 3)
    {
        /* traditional signature algos */
        sprintf(certpath, "%s%s%s%s", certsdir, sig_name, sep, "cert.pem");
        sprintf(privkeypath, "%s%s%s%s", certsdir, sig_name, sep, "key.pem");
    } else if (sig_index < 3)
    {
        is_oqs_auth = 1;
        /* post quantum signature algos */
        sprintf(certpath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.crt");
        sprintf(privkeypath, "%s%s%s%s%s", certsdir, sig_name, sep, sig_name, "_srv.key");
    } else
    {
        is_hsig_auth = 1;
        /* hsig: use traditional signature algos cert&key for now */
        sprintf(certpath, "%s%s%s%s", certsdir, "ecdsa", sep, "cert.pem");
        sprintf(privkeypath, "%s%s%s%s", certsdir, "ecdsa", sep, "key.pem");
    }
    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;
    ptls_iovec_t cert;

    setup_certificate(&cert, certpath);
    setup_private_key(&openssl_sign_certificate, privkeypath, sig_name, is_oqs_auth);

    /* setup ca cert file */
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, NULL);

    /* CN in certificate
     * rsa: rsa.test.example.com
     * ed25519: ed25519.test.example.com
     * others: test.example.com*/
    const char *server_name = (strcmp(sig_name, "rsa") == 0) ? "rsa.test.example.com" :
                              (strcmp(sig_name, "ed25519") == 0) ? "ed25519.test.example.com" :
                                                                 "test.example.com";

    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges, /*ptls_openssl_key_exchanges by default*/
                          .cipher_suites = ptls_openssl_cipher_suites_all, /*ptls_openssl_cipher_suites_all by default*/
                          .certificates = {&cert, 1},
                          .ech = {.client = {NULL}, .server = {NULL}}, /* ech is disabled */
                          .sign_certificate = &openssl_sign_certificate.super,
                          .verify_certificate = &openssl_verify_certificate.super,
                          .require_oqssig_on_auth = is_oqs_auth,/* oqs auth enabled at client side */
                          .require_hsig_on_auth = is_hsig_auth,/* hsig auth enabled at client side */
    };
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}}}};

    /* setup log*/

    /* run client TODO: set the arguments*/
    double a, b;
    return run_one_client(host, port, &ctx, server_name, NULL, &client_hs_prop);


Exit:
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(oqsprovider);
#endif
    exit(1);
}
