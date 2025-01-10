//
// Created by xinshu on 09/01/25.
//
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "utilities.h"

ptls_context_t *ctx, *ctx_peer;

static void ben_run_handshake(ptls_iovec_t ticket, int mode, int expect_ticket, int check_ch, int require_client_authentication,
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

    if (check_ch)
        ctx->verify_certificate = verify_certificate;

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

    if (can_ech(ctx, 0)) {
        ptls_set_server_name(client, "test.example.com", 0);
        client_hs_prop.client.ech.configs = ptls_iovec_init(ECH_CONFIG_LIST, sizeof(ECH_CONFIG_LIST) - 1);
    }

    static ptls_on_extension_t cb = {on_extension_cb};
    ctx_peer->on_extension = &cb;

    if (require_client_authentication)
        ctx_peer->require_client_authentication = 1;

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

    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);

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
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);

    if (require_client_authentication) {
        /* at the moment, async sign-certificate is not supported in this path, neither on the client-side or the server-side */
        ok(ptls_is_psk_handshake(server) == 0);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    } else if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        ok(ret == 0);
    } else {
        ok(ret == 0 || ret == PTLS_ERROR_ASYNC_OPERATION);
    }

    ok(sbuf.off != 0);
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
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
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
        ok(consumed == cbuf.off);
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
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    } else {
        ok(ret == 0);
    }

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(cbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(client) != NULL);
        ok(strcmp(ptls_get_server_name(client), "test.example.com") == 0);
        ok(ptls_get_negotiated_protocol(client) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(client), "h2") == 0);
    } else {
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (expect_ticket) {
        ok(consumed < sbuf.off);
        memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
        sbuf.off -= consumed;
    } else {
        ok(consumed == sbuf.off);
        sbuf.off = 0;
    }

    if (require_client_authentication) {
        ok(!ptls_handshake_is_complete(server));
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        ok(ret == 0);
        ok(ptls_handshake_is_complete(server));
        cbuf.off = 0;
    }

    /* holds the ptls_t pointer of server prior to migration */
    ptls_t *original_server = server;

    if (mode != TEST_HANDSHAKE_EARLY_DATA || require_client_authentication) {
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, strlen(req)) == 0);
        ok(ptls_handshake_is_complete(server));
        decbuf.off = 0;
        cbuf.off = 0;
        if (transfer_session)
            server = clone_tls(original_server);

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        ok(ret == 0);
    }

    consumed = sbuf.off;
    ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
    ok(ret == 0);
    ok(consumed == sbuf.off);
    ok(decbuf.off == strlen(resp));
    ok(memcmp(decbuf.base, resp, strlen(resp)) == 0);
    ok(ptls_handshake_is_complete(client));
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

    if (mode == TEST_HANDSHAKE_KEY_UPDATE) {
        /* server -> client with update_request */
        ret = ptls_update_key(server, 1);
        ok(ret == 0);
        ok(server->needs_key_update);
        ok(server->key_update_send_request);
        ret = ptls_send(server, &sbuf, "good bye", 8);
        ok(ret == 0);
        ok(!server->needs_key_update);
        ok(!server->key_update_send_request);
        consumed = sbuf.off;
        ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
        ok(ret == 0);
        ok(sbuf.off == consumed);
        ok(decbuf.off == 8);
        ok(memcmp(decbuf.base, "good bye", 8) == 0);
        ok(client->needs_key_update);
        ok(!client->key_update_send_request);
        sbuf.off = 0;
        decbuf.off = 0;
        ret = ptls_send(client, &cbuf, "hello", 5);
        ok(ret == 0);
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(cbuf.off == consumed);
        ok(decbuf.off == 5);
        ok(memcmp(decbuf.base, "hello", 5) == 0);
        cbuf.off = 0;
        decbuf.off = 0;
    }

    /* original_server is used for the server-side checks because handshake data is never migrated */
    if (can_ech(ctx_peer, 1) && can_ech(ctx, 0)) {
        ok(ptls_is_ech_handshake(client, NULL, NULL, NULL));
        ok(ptls_is_ech_handshake(original_server, NULL, NULL, NULL));
    } else {
        ok(!ptls_is_ech_handshake(client, NULL, NULL, NULL));
        ok(!ptls_is_ech_handshake(original_server, NULL, NULL, NULL));
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

static int bench_handshake()
{
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

    setup_certificate(&cert, certpath);
    setup_private_key(&openssl_sign_certificate, privkeypath, sig_name, is_oqs_sig);

    /* setup ca cert file */
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, NULL);

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






#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(oqsprovider);
#endif
    return 0;
}