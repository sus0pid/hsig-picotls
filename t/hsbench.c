#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"
#include "../deps/picotest/picotest.h"

#define BENCH_BATCH 1000
ptls_context_t *ctx, *ctx_peer;
static unsigned server_sc_callcnt, client_sc_callcnt, async_sc_callcnt;


/* Time in microseconds */
static uint64_t bench_time()
{
    struct timeval tv;
#ifdef CLOCK_PROCESS_CPUTIME_ID
    struct timespec cpu;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu) == 0) {
        uint64_t nanos = (uint64_t)cpu.tv_nsec;
        uint64_t micros = nanos / 1000;
        micros += (1000000ull) * ((uint64_t)cpu.tv_sec);
        return micros;
    }
#endif
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static int bench_basic(uint64_t *x)
{
    uint64_t t_start = bench_time();
    uint32_t a = (uint32_t)((*x) & 0xFFFFFFFF);
    uint32_t b = (uint32_t)((*x) >> 32);

    /* Evaluate the current CPU. The benchmark is designed to
     * emulate typical encryption operations, hopefully so it
     * will not be compiled out by the optimizer. */
    for (unsigned int i = 0; i < 10000000; i++) {
        uint32_t v = (a >> 3) | (a << 29);
        v += a;
        v ^= b;
        b = a;
        a = v;
    }
    *x = (((uint64_t)b) << 32) | a;

    return (int)(bench_time() - t_start);
}

enum {
    TEST_HANDSHAKE_1RTT,
    TEST_HANDSHAKE_2RTT,
    TEST_HANDSHAKE_HRR,
    TEST_HANDSHAKE_HRR_STATELESS,
    TEST_HANDSHAKE_EARLY_DATA,
    TEST_HANDSHAKE_KEY_UPDATE
};

static int save_client_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    ptls_set_server_name(tls, (const char *)params->server_name.base, params->server_name.len);
    if (params->negotiated_protocols.count != 0)
        ptls_set_negotiated_protocol(tls, (const char *)params->negotiated_protocols.list[0].base,
                                     params->negotiated_protocols.list[0].len);
    return 0;
}

static int on_extension_cb(ptls_on_extension_t *self, ptls_t *tls, uint8_t hstype, uint16_t exttype, ptls_iovec_t extdata)
{
    assert(extdata.base);
    return 0;
}

static int can_ech(ptls_context_t *ctx, int is_server)
{
    if (is_server) {
        return ctx->ech.server.create_opener != NULL;
    } else {
        return ctx->ech.client.ciphers != NULL;
    }
}

static void test_handshake(ptls_iovec_t ticket, int mode, int expect_ticket, int check_ch, int require_client_authentication,
                           int transfer_session)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ticket}}}, server_hs_prop = {{{{NULL}}}};
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed, max_early_data_size = 0;
    int ret;
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n";

    client_sc_callcnt = 0;
    server_sc_callcnt = 0;
    async_sc_callcnt = 0;

    client = ptls_new(ctx, 0);
    server = ptls_new(ctx_peer, 1);
    ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
    ptls_buffer_init(&sbuf, sbuf_small, sizeof(sbuf_small));
    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    if (check_ch) {
        static ptls_on_client_hello_t cb = {save_client_hello};
        ctx_peer->on_client_hello = &cb;
        static const ptls_iovec_t protocols[] = {{(uint8_t *)"h2", 2}, {(uint8_t *)"http/1.1", 8}};
        client_hs_prop.client.negotiated_protocols.list = protocols;
        client_hs_prop.client.negotiated_protocols.count = PTLS_ELEMENTSOF(protocols);
        ptls_set_server_name(client, "test.example.com", 0);
    }

//    if (can_ech(ctx, 0)) {
//        ptls_set_server_name(client, "test.example.com", 0);
//        client_hs_prop.client.ech.configs = ptls_iovec_init(ECH_CONFIG_LIST, sizeof(ECH_CONFIG_LIST) - 1);
//    }

    static ptls_on_extension_t cb = {on_extension_cb};
    ctx_peer->on_extension = &cb;

    if (require_client_authentication)
        ctx_peer->require_client_authentication = 1; /*mTLS*/

    switch (mode) {
    case TEST_HANDSHAKE_HRR:
        client_hs_prop.client.negotiate_before_key_exchange = 1;
        break;
    case TEST_HANDSHAKE_HRR_STATELESS:
        client_hs_prop.client.negotiate_before_key_exchange = 1;
        server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef0123456789abcdef";
        server_hs_prop.server.retry_uses_cookie = 1;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        assert(ctx_peer->max_early_data_size != 0);
        client_hs_prop.client.max_early_data_size = &max_early_data_size;
        break;
    }

    /*1. client CHLO*/
    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    printf("- Client sent CHLO\n\n");
//    ok(ret == PTLS_ERROR_IN_PROGRESS);
//    ok(cbuf.off != 0);

    switch (mode) {
    case TEST_HANDSHAKE_2RTT:
    case TEST_HANDSHAKE_HRR:
    case TEST_HANDSHAKE_HRR_STATELESS:
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        if (mode == TEST_HANDSHAKE_HRR_STATELESS) {
            ok(ret == PTLS_ERROR_STATELESS_RETRY);
            ptls_free(server);
            server = ptls_new(ctx_peer, 1);
        } else {
            ok(ret == PTLS_ERROR_IN_PROGRESS);
        }
        ok(cbuf.off == consumed);
        ok(sbuf.off != 0);
        cbuf.off = 0;
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_hs_prop);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(sbuf.off == consumed);
        ok(cbuf.off != 0);
        sbuf.off = 0;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        ok(max_early_data_size == ctx_peer->max_early_data_size);
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);
        break;
    }

    consumed = cbuf.off;
    /*2. server CHLO + SHLO + EE + CertRequest + Cert + CertVerify*/
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    printf("- Server received CHLO and sent SHLO+EE+Auth+Finished\n\n");
    if (require_client_authentication) {
        /* at the moment, async sign-certificate is not supported in this path, neither on the client-side or the server-side */
//        ok(ptls_is_psk_handshake(server) == 0);
//        ok(ret == PTLS_ERROR_IN_PROGRESS);
        printf("- mTLS enabled\n");
    } else if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        ok(ret == 0);
    } else {
        ok(ret == 0 || ret == PTLS_ERROR_ASYNC_OPERATION);
    }

//    ok(sbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(server) != NULL);
        if (can_ech(ctx, 0) && !can_ech(ctx_peer, 1)) {
            /* server should be using CHouter.sni that includes the public name of the ECH extension */
            ok(strcmp(ptls_get_server_name(server), "example.com") == 0);
        } else {
            ok(strcmp(ptls_get_server_name(server), "test.example.com") == 0);
        }
        ok(ptls_get_negotiated_protocol(server) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(server), "h2") == 0);
    } else {
//        ok(ptls_get_server_name(server) == NULL);
//        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (mode == TEST_HANDSHAKE_EARLY_DATA && !require_client_authentication) {
        ok(consumed < cbuf.off);
        memmove(cbuf.base, cbuf.base + consumed, cbuf.off - consumed);
        cbuf.off -= consumed;

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, decbuf.off) == 0);
        ok(!ptls_handshake_is_complete(server));
        cbuf.off = 0;
        decbuf.off = 0;

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        ok(ret == 0);
    } else {
//        ok(consumed == cbuf.off);
        cbuf.off = 0;
    }

    while (ret == PTLS_ERROR_ASYNC_OPERATION) {
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(consumed == sbuf.off);
        ok(cbuf.off == 0);
        sbuf.off = 0;
        ret = ptls_handshake(server, &sbuf, NULL, NULL, &server_hs_prop);
    }
    if (require_client_authentication) {
//        ok(ret == PTLS_ERROR_IN_PROGRESS);
    } else {
        ok(ret == 0);
    }

    consumed = sbuf.off;
    /*3. client Cert + CertVerify + Finished*/
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    printf("- Client sent Auth: Cert + CertVef + Finished\n\n");
//    ok(ret == 0);
//    ok(cbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(client) != NULL);
        ok(strcmp(ptls_get_server_name(client), "test.example.com") == 0);
        ok(ptls_get_negotiated_protocol(client) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(client), "h2") == 0);
    } else {
//        ok(ptls_get_server_name(server) == NULL);
//        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (expect_ticket) {
        ok(consumed < sbuf.off);
        memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
        sbuf.off -= consumed;
    } else {
//        ok(consumed == sbuf.off);
        sbuf.off = 0;
    }

    if (require_client_authentication) {
        if (ptls_handshake_is_complete(client))
            printf(">>Client handshake is complete\n");
        else
            printf(">>Client handshake is not complete\n");
        if (ptls_handshake_is_complete(server))
            printf(">>Server handshake is complete\n");
        else
            printf(">>Server handshake is not complete\n");
//        ok(!ptls_handshake_is_complete(server));
        consumed = cbuf.off;
        /*4. server Finished*/
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        printf("- Server received client Auth + Finished\n\n");
//        ok(ret == 0);
//        ok(ptls_handshake_is_complete(server));
        cbuf.off = 0;
    }

    /* holds the ptls_t pointer of server prior to migration */
    ptls_t *original_server = server;

    if (mode != TEST_HANDSHAKE_EARLY_DATA || require_client_authentication) {
        ret = ptls_send(client, &cbuf, req, strlen(req));
        printf("- Client sent app message: %s\n\n", req);
//        ok(ret == 0);

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        printf("- Server received client request\n\n");
//        ok(ret == 0);
//        ok(consumed == cbuf.off);
//        ok(decbuf.off == strlen(req));
//        ok(memcmp(decbuf.base, req, strlen(req)) == 0);
//        ok(ptls_handshake_is_complete(server));
        decbuf.off = 0;
        cbuf.off = 0;
//        if (transfer_session)
//            server = clone_tls(original_server);

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        printf("\n- Server sent response: %s\n\n", resp);
//        ok(ret == 0);
    }

    consumed = sbuf.off;
    ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
    printf("\n- Client received server response\n\n");
//    ok(ret == 0);
//    ok(consumed == sbuf.off);
//    ok(decbuf.off == strlen(resp));
//    ok(memcmp(decbuf.base, resp, strlen(resp)) == 0);
//    ok(ptls_handshake_is_complete(client));
    decbuf.off = 0;
    sbuf.off = 0;

    if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(cbuf.off == consumed);
        ok(decbuf.off == 0);
        ok(ptls_handshake_is_complete(client));
        cbuf.off = 0;
    }

    // remove code related to key update
//    if (mode == TEST_HANDSHAKE_KEY_UPDATE) {
//        /* server -> client with update_request */
//        ret = ptls_update_key(server, 1);
//        ok(ret == 0);
//        ok(server->needs_key_update);
//        ok(server->key_update_send_request);
//        ret = ptls_send(server, &sbuf, "good bye", 8);
//        ok(ret == 0);
//        ok(!server->needs_key_update);
//        ok(!server->key_update_send_request);
//        consumed = sbuf.off;
//        ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
//        ok(ret == 0);
//        ok(sbuf.off == consumed);
//        ok(decbuf.off == 8);
//        ok(memcmp(decbuf.base, "good bye", 8) == 0);
//        ok(client->needs_key_update);
//        ok(!client->key_update_send_request);
//        sbuf.off = 0;
//        decbuf.off = 0;
//        ret = ptls_send(client, &cbuf, "hello", 5);
//        ok(ret == 0);
//        consumed = cbuf.off;
//        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
//        ok(ret == 0);
//        ok(cbuf.off == consumed);
//        ok(decbuf.off == 5);
//        ok(memcmp(decbuf.base, "hello", 5) == 0);
//        cbuf.off = 0;
//        decbuf.off = 0;
//    }

    /* original_server is used for the server-side checks because handshake data is never migrated */
    if (can_ech(ctx_peer, 1) && can_ech(ctx, 0)) {
        ok(ptls_is_ech_handshake(client, NULL, NULL, NULL));
        ok(ptls_is_ech_handshake(original_server, NULL, NULL, NULL));
    } else {
//        ok(!ptls_is_ech_handshake(client, NULL, NULL, NULL));
//        ok(!ptls_is_ech_handshake(original_server, NULL, NULL, NULL));
    }

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    if (original_server != server)
        ptls_free(original_server);
    ptls_free(server);

    if (check_ch)
        ctx_peer->on_client_hello = NULL;

    ctx->verify_certificate = NULL;
    if (require_client_authentication)
        ctx_peer->require_client_authentication = 0;
}

int main(int argc, char **argv)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Explicitly load the legacy provider in addition to default, as we test Blowfish in one of the tests. */
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(NULL, "default");
#elif !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    res_init();

    int ret = 0;
    uint64_t x = 0xdeadbeef;
    uint64_t s = 0;
    int basic_ref = bench_basic(&x);
    char OS[128];
    char HW[128];
    struct utsname uts;
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
    if (argc > 1) {
        fprintf(stderr, "Usage: %s [-f]\n   Use option \"-f\" to force execution of the slower tests.\n", argv[0]);
        exit(-1);
    }


    // setup ptls handshake configuration
    // run client and server together

//    ptls_openssl_sign_certificate_t openssl_sign_certificate;
//    ptls_openssl_verify_certificate_t openssl_verify_certificate;
//    ptls_ech_create_opener_t ech_create_opener = {.cb = create_ech_opener};

    const char *ca_cert_path = "t/assets/test-ca.crt";
    const char *cert_path = "t/assets/rsa/cert.pem"; /*client and server using the same cert*/
    const char *key_path = "t/assets/rsa/key.pem";


    /* we should call X509_STORE_free on OpenSSL 1.1 or in prior versions decrement refount then call _free */
    ptls_context_t openssl_ctx = {.random_bytes = ptls_openssl_random_bytes,
                                  .get_time = &ptls_get_time,
                                  .key_exchanges = ptls_openssl_key_exchanges,
                                  .cipher_suites = ptls_openssl_cipher_suites_all,
                                  .ech = {.client = {NULL},
                                          .server = {NULL /* activated by -K option */}}};

    load_certificate_chain(&openssl_ctx, cert_path); /*load certificate*/
    load_private_key(&openssl_ctx, key_path); /*load private key*/
    setup_verify_certificate(&openssl_ctx, ca_cert_path); /*load ca root cert*/
    ptls_handshake_properties_t hsprop = {{{{NULL}}}};

    ctx = ctx_peer = &openssl_ctx;

    // run handshake here
    // full handshake with client authentication without ech
    printf("Running handshake bench test ...\n");

    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0, 1, 0);







    printf(
        "OS, HW, bits, batch, 10M ops\n");
    printf("%s, %s, %d, %d, %d\n", OS, HW, (int)(8 * sizeof(size_t)), BENCH_BATCH, basic_ref);


    return ret;
}