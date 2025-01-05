//
// Created by xinshu on 21/03/24.
// gcc test_picotls_api.c -lpicotls-openssl -lpicotls-core -lssl -lcrypto -o test_picotls_api -I include -L newlib
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
#include <openssl/x509_vfy.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "test_picotls_api.h"

ptls_context_t *ctx, *ctx_peer;


static void test_handshake_api(void)
{
    ptls_t *client, *server;
    traffic_secrets_t client_secrets = {{{0}}}, server_secrets = {{{0}}};
    ptls_buffer_t cbuf, sbuf;
    size_t coffs[5] = {0}, soffs[5];
    ptls_update_traffic_key_t update_traffic_key = {on_update_traffic_key};
    ptls_encrypt_ticket_t encrypt_ticket = {on_copy_ticket};
    ptls_save_ticket_t save_ticket = {on_save_ticket};
    int ret;

    ctx->update_traffic_key = &update_traffic_key;
    ctx->omit_end_of_early_data = 1;
    ctx->save_ticket = &save_ticket;
    //    ctx->save_ticket = NULL;
    ctx_peer->update_traffic_key = &update_traffic_key;
    ctx_peer->omit_end_of_early_data = 1;
    ctx_peer->encrypt_ticket = &encrypt_ticket;
    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;

    saved_ticket = ptls_iovec_init(NULL, 0);

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);

    client = ptls_new(ctx, 0);
    *ptls_get_data_ptr(client) = &client_secrets;
    server = ptls_new(ctx_peer, 1);
    *ptls_get_data_ptr(server) = &server_secrets;

    if(!disable_debug) {
        /* Test1: full handshake */
        /* C1. client gen CHLO*/
        printf("\n\n-------------------------------Test0: full handshake--------------------\n");
        ptls_set_server_name(client, "test.example.com", 0);
        ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, NULL);
        if (!disable_debug) {
            printf(">>Client send CHLO.\n");
            //        printf(">>Client secrets:");
            //        print_traffic_secrets(client_secrets);
            if (ptls_handshake_is_complete(client))
                printf(">>Client handshake is complete\n");
            else
                printf(">>Client handshake is not complete\n");
        }

        assert(ret == PTLS_ERROR_IN_PROGRESS);
        /* S1. suppose server receive CHLO*/
        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
        if (!disable_debug) {
            printf(">>Server receive CHLO and send SHLO+FIN\n");
            //        printf(">>Server secrets:");
            //        print_traffic_secrets(server_secrets);
            if (ptls_handshake_is_complete(server))
                printf(">>Server handshake is complete\n");
            else
                printf(">>Server handshake is not complete\n");

        }
        assert(ret == 0);
        assert(sbuf.off != 0);
        assert(!ptls_handshake_is_complete(server));
        assert(memcmp(server_secrets[1][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
        assert(memcmp(server_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
        assert(memcmp(server_secrets[0][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
        assert(memcmp(server_secrets[0][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
        ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, NULL);
        if (!disable_debug) {
            printf(">>Client receive SHLO+FIN and send FIN\n");
            //        printf(">>Client secrets:");
            //        print_traffic_secrets(client_secrets);
            if (ptls_handshake_is_complete(client))
                printf(">>Client handshake is complete\n");
        }
        assert(ret == 0);
        assert(cbuf.off != 0);
        assert(ptls_handshake_is_complete(client));
        assert(memcmp(client_secrets[0][2], server_secrets[1][2], PTLS_MAX_DIGEST_SIZE) == 0);
        assert(memcmp(client_secrets[1][2], server_secrets[0][2], PTLS_MAX_DIGEST_SIZE) == 0);
        assert(memcmp(client_secrets[0][3], server_secrets[1][3], PTLS_MAX_DIGEST_SIZE) == 0);
        assert(memcmp(client_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
        if (!disable_debug) {
            printf(">>Server receive FIN\n");
            //        printf(">>Server secrets:");
            //        print_traffic_secrets(server_secrets);
            if (ptls_handshake_is_complete(server))
                printf(">>Server handshake is complete\n");
        }
        assert(ret == 0);
        assert(sbuf.off == 0);
        assert(ptls_handshake_is_complete(server));
        assert(memcmp(client_secrets[1][3], server_secrets[0][3], PTLS_MAX_DIGEST_SIZE) == 0);

        ptls_free(client);
        ptls_free(server);

        cbuf.off = 0;
        sbuf.off = 0;
        memset(client_secrets, 0, sizeof(client_secrets));
        memset(server_secrets, 0, sizeof(server_secrets));
        memset(coffs, 0, sizeof(coffs));
        memset(soffs, 0, sizeof(soffs));
    }

    ////    ctx->save_ticket = NULL; /* don't allow further test to update the saved ticket */
    //    if(disable_debug) {
    //        /* Test2: 0-RTT resumption */
    //        printf("\n\n-------------------------------Test2: 0-RTT resumption--------------------\n");
    //        size_t max_early_data_size = 0;
    //        /* read ticket from file*/
    //        FILE *fp = fopen(TICKET_PATH, "rb");
    //        assert(fp != NULL);
    //        fseek(fp, 0, SEEK_END);
    //        size_t fplen = ftell(fp);
    //        fseek(fp, 0, SEEK_SET);
    //        saved_ticket.base = malloc(fplen);
    //        assert(saved_ticket.base != NULL);
    //        size_t bytes_read = fread(saved_ticket.base, sizeof(uint8_t), fplen, fp);
    //        assert(bytes_read == fplen);
    //        saved_ticket.len = fplen;
    //
    //        /* start handshake */
    //        ptls_handshake_properties_t client_hs_prop = {{{{NULL}, saved_ticket, &max_early_data_size}}};
    //        client = ptls_new(ctx, 0);
    //        *ptls_get_data_ptr(client) = &client_secrets;
    //        server = ptls_new(ctx_peer, 1);
    //        *ptls_get_data_ptr(server) = &server_secrets;
    //        ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, &client_hs_prop);
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(max_early_data_size != 0);
    //        assert(memcmp(client_secrets[1][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //        if (!disable_debug) {
    //            printf(">>Client send CHLO.\n");
    ////        printf(">>Client saved ticket:\n");
    ////        print_base(saved_ticket.base, saved_ticket.len);
    //            printf(">>Client secrets:");
    //            print_traffic_secrets(client_secrets);
    //            if (ptls_handshake_is_complete(client))
    //                printf(">>Client handshake is complete\n");
    //            else
    //                printf(">>Client handshake is not complete\n");
    //        }
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    //        if (!disable_debug) {
    //            printf(">>Server receive CHLO and send SHLO+FIN\n");
    //            printf(">>Server secrets:");
    //            print_traffic_secrets(server_secrets);
    //            if (ptls_handshake_is_complete(server))
    //                printf(">>Server handshake is complete\n");
    //            else
    //                printf(">>Server handshake is not complete\n");
    //
    //        }
    //        assert(ret == 0);
    //        assert(sbuf.off != 0);
    //        assert(!ptls_handshake_is_complete(server));
    //        assert(memcmp(client_secrets[1][1], server_secrets[0][1], PTLS_MAX_DIGEST_SIZE) == 0);
    //        assert(memcmp(server_secrets[0][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0); /* !!!overlap!!! */
    //        assert(memcmp(server_secrets[1][2], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //        assert(memcmp(server_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //        assert(memcmp(server_secrets[0][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    //        /* send early data */
    //        ret = ptls_send(client, &cbuf, "hello world", 11); /* client send 0-RTT data that'll be rejected */
    //        printf(">>Client send early data: hello world\n");
    //        assert(ret == 0);
    //        size_t inlen = cbuf.off;
    //        /* receive early datat */
    //        ret = ptls_receive(server, &sbuf, cbuf.base, inlen);
    //        assert(ret == 0);
    //        printf(">>Server received early data:\n");
    //        write(1, sbuf.base, sbuf.off);
    //
    //        ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop);
    //        if (!disable_debug) {
    //            printf(">>Client receive SHLO+FIN and send FIN\n");
    ////        printf(">>Client secrets:");
    ////        print_traffic_secrets(client_secrets);
    //            if (ptls_handshake_is_complete(client))
    //                printf(">>Client handshake is complete\n");
    //        }
    //        assert(ret == 0);
    //        assert(cbuf.off != 0);
    //        assert(ptls_handshake_is_complete(client));
    //        assert(memcmp(client_secrets[0][3], server_secrets[1][3], PTLS_MAX_DIGEST_SIZE) == 0);
    //        assert(memcmp(client_secrets[1][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    //        if (!disable_debug) {
    //            printf(">>Server receive FIN\n");
    ////        printf(">>Server secrets:");
    ////        print_traffic_secrets(server_secrets);
    //            if (ptls_handshake_is_complete(server))
    //                printf(">>Server handshake is complete\n");
    //        }
    //        assert(ret == 0);
    //        assert(sbuf.off == 0);
    //        assert(ptls_handshake_is_complete(server));
    //        assert(memcmp(server_secrets[0][3], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //
    //        ptls_free(client);
    //        ptls_free(server);
    //
    //        cbuf.off = 0;
    //        sbuf.off = 0;
    //        memset(client_secrets, 0, sizeof(client_secrets));
    //        memset(server_secrets, 0, sizeof(server_secrets));
    //        memset(coffs, 0, sizeof(coffs));
    //        memset(soffs, 0, sizeof(soffs));
    //    }
    //
    //    if(disable_debug) {
    //        /* 0-RTT rejection */
    //        printf("\n\n-------------------------------Test3: 0-RTT rejection--------------------\n");
    //        ctx_peer->max_early_data_size = 0;
    ////        client_hs_prop = (ptls_handshake_properties_t) {{{{NULL}, saved_ticket, &max_early_data_size}}};
    //        client = ptls_new(ctx, 0);
    //        *ptls_get_data_ptr(client) = &client_secrets;
    //        server = ptls_new(ctx_peer, 1);
    //        *ptls_get_data_ptr(server) = &server_secrets;
    //        ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, &client_hs_prop);
    //        if (!disable_debug) {
    //            printf(">>Client send CHLO.\n");
    //            printf(">>Client saved ticket:\n");
    //            print_base(saved_ticket.base, saved_ticket.len);
    //            printf(">>Client secrets:");
    //            print_traffic_secrets(client_secrets);
    //            if (ptls_handshake_is_complete(client))
    //                printf(">>Client handshake is complete\n");
    //            else
    //                printf(">>Client handshake is not complete\n");
    //        }
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(max_early_data_size != 0);
    //        assert(memcmp(client_secrets[1][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    //        if (!disable_debug) {
    //            printf(">>Server receive CHLO and send SHLO+FIN\n");
    //            printf(">>Server secrets:");
    //            print_traffic_secrets(server_secrets);
    //            if (ptls_handshake_is_complete(server))
    //                printf(">>Server handshake is complete\n");
    //            else
    //                printf(">>Server handshake is not complete\n");
    //
    //        }
    //        assert(ret == 0);
    //        assert(sbuf.off != 0);
    //        assert(!ptls_handshake_is_complete(server));
    //        ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop);
    //        if (!disable_debug) {
    //            printf(">>Client receive SHLO+FIN and send FIN\n");
    //            printf(">>Client secrets:");
    //            print_traffic_secrets(client_secrets);
    //            if (ptls_handshake_is_complete(client))
    //                printf(">>Client handshake is complete\n");
    //        }
    //        assert(ret == 0);
    //        assert(cbuf.off != 0);
    //        assert(ptls_handshake_is_complete(client));
    //        assert(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
    //        assert(memcmp(server_secrets[0][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, NULL);
    //        if (!disable_debug) {
    //            printf(">>Server receive FIN\n");
    //            printf(">>Server secrets:");
    //            print_traffic_secrets(server_secrets);
    //            if (ptls_handshake_is_complete(server))
    //                printf(">>Server handshake is complete\n");
    //        }
    //        assert(ret == 0);
    //        assert(sbuf.off == 0);
    //        assert(ptls_handshake_is_complete(server));
    //
    //        ptls_free(client);
    //        ptls_free(server);
    //
    //
    //        cbuf.off = 0;
    //        sbuf.off = 0;
    //        memset(client_secrets, 0, sizeof(client_secrets));
    //        memset(server_secrets, 0, sizeof(server_secrets));
    //        memset(coffs, 0, sizeof(coffs));
    //        memset(soffs, 0, sizeof(soffs));
    //    }
    //
    //    if(disable_debug) {
    //
    //        /* HRR rejects 0-RTT */
    //        ctx_peer->max_early_data_size = 8192;
    //        ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};
    //        server_hs_prop.server.enforce_retry = 1;
    //        client_hs_prop = (ptls_handshake_properties_t) {{{{NULL}, saved_ticket, &max_early_data_size}}};
    //        client = ptls_new(ctx, 0);
    //        *ptls_get_data_ptr(client) = &client_secrets;
    //        server = ptls_new(ctx_peer, 1);
    //        *ptls_get_data_ptr(server) = &server_secrets;
    //        ret = ptls_handle_message(client, &cbuf, coffs, 0, NULL, 0, &client_hs_prop); /* -> CH */
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(max_early_data_size != 0);
    //        assert(memcmp(client_secrets[1][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) != 0);
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, &server_hs_prop); /* CH -> HRR */
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(sbuf.off != 0);
    //        assert(!ptls_handshake_is_complete(server));
    //        ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop); /* HRR  -> CH */
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(cbuf.off != 0);
    //        assert(!ptls_handshake_is_complete(client));
    //        assert(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, &server_hs_prop); /* CH -> SH..SF */
    //        assert(ret == 0);
    //        assert(!ptls_handshake_is_complete(server));
    //        assert(memcmp(server_secrets[0][1], zeroes_of_max_digest_size, PTLS_MAX_DIGEST_SIZE) == 0);
    //        assert(sbuf.off != 0);
    //        ret = feed_messages(client, &cbuf, coffs, sbuf.base, soffs, &client_hs_prop); /* SH..SF -> CF */
    //        assert(ret == 0);
    //        assert(ptls_handshake_is_complete(client));
    //        assert(cbuf.off != 0);
    //        ret = feed_messages(server, &sbuf, soffs, cbuf.base, coffs, &server_hs_prop); /* CF -> */
    //        assert(ret == 0);
    //        assert(ptls_handshake_is_complete(server));
    //
    //        ptls_free(client);
    //        ptls_free(server);
    //
    //        cbuf.off = 0;
    //        sbuf.off = 0;
    //
    //
    //        printf("\n\n-------------------------------Test3: 0-RTT with early data--------------------\n");
    //        /* shamelessly reuse this subtest for testing ordinary TLS 0-RTT with HRR rejection */
    //        ctx->update_traffic_key = NULL;
    //        ctx->omit_end_of_early_data = 0;
    //        ctx_peer->update_traffic_key = NULL;
    //        ctx_peer->omit_end_of_early_data = 0;
    //        client_hs_prop = (ptls_handshake_properties_t) {{{{NULL}, saved_ticket, &max_early_data_size}}};
    //        server_hs_prop.server.enforce_retry = 1;
    //        client = ptls_new(ctx, 0);
    //        server = ptls_new(ctx_peer, 1);
    //        ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop); /* -> CH */
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(client_hs_prop.client.max_early_data_size != 0);
    //        assert(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
    //        assert(cbuf.off != 0);
    //        ret = ptls_send(client, &cbuf, "hello world", 11); /* send 0-RTT data that'll be rejected */
    //        assert(ret == 0);
    //        size_t inlen = cbuf.off;
    //        ret = ptls_handshake(server, &sbuf, cbuf.base, &inlen, &server_hs_prop); /* CH -> HRR */
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(cbuf.off == inlen);
    //        cbuf.off = 0;
    //        assert(sbuf.off != 0);
    //        inlen = sbuf.off;
    //        ret = ptls_handshake(client, &cbuf, sbuf.base, &inlen, &client_hs_prop); /* HRR -> CH */
    //        assert(ret == PTLS_ERROR_IN_PROGRESS);
    //        assert(client_hs_prop.client.early_data_acceptance == PTLS_EARLY_DATA_REJECTED);
    //        assert(sbuf.off == inlen);
    //        sbuf.off = 0;
    //        assert(cbuf.off != 0);
    //        inlen = cbuf.off;
    //        ret = ptls_handshake(server, &sbuf, cbuf.base, &inlen, &server_hs_prop); /* CH -> SH..SF,NST */
    //        assert(ret == 0);
    //        assert(!ptls_handshake_is_complete(server));
    //        assert(cbuf.off == inlen);
    //        cbuf.off = 0;
    //        assert(sbuf.off != 0);
    //        inlen = sbuf.off;
    //        ret = ptls_handshake(client, &cbuf, sbuf.base, &inlen, &client_hs_prop); /* SH..SF -> CF */
    //        assert(ret == 0);
    //        assert(ptls_handshake_is_complete(client));
    //        assert(inlen < sbuf.off); /* ignore NST */
    //        sbuf.off = 0;
    //        inlen = cbuf.off;
    //        ret = ptls_handshake(server, &sbuf, cbuf.base, &inlen, &server_hs_prop); /* CF -> */
    //        assert(ret == 0);
    //        assert(ptls_handshake_is_complete(server));
    //        assert(sbuf.off == 0);
    //
    //
    //        ptls_free(client);
    //        ptls_free(server);
    //    }

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);

    ctx->update_traffic_key = NULL;
    ctx->omit_end_of_early_data = 0;
    ctx->save_ticket = NULL;
    ctx_peer->update_traffic_key = NULL;
    ctx_peer->omit_end_of_early_data = 0;
    ctx_peer->encrypt_ticket = NULL;
    ctx_peer->save_ticket = NULL;
    ctx_peer->ticket_lifetime = 0;
    ctx_peer->max_early_data_size = 0;
}

static void test_early_data()
{
    printf("\n\n-------------------------------Test1: 0-rtt handshake with early data--------------------\n");
    /* read ticket from file*/
    saved_ticket = ptls_iovec_init(NULL, 0);
    FILE *fp = fopen(TICKET_PATH, "rb");
    assert(fp != NULL);
    fseek(fp, 0, SEEK_END);
    size_t fplen = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    saved_ticket.base = malloc(fplen);
    assert(saved_ticket.base != NULL);
    size_t bytes_read = fread(saved_ticket.base, sizeof(uint8_t), fplen, fp);
    assert(bytes_read == fplen);
    saved_ticket.len = fplen;
    fclose(fp);
    printf(">>client load ticket:\n");
    print_base(saved_ticket.base, saved_ticket.len);

    assert(ctx->key_exchanges[0]->id == ctx_peer->key_exchanges[0]->id);
    assert(ctx->key_exchanges[1] == NULL);
    assert(ctx_peer->key_exchanges[1] == NULL);

    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, saved_ticket}}}, server_hs_prop = {{{{NULL}}}};
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed, max_early_data_size = 0;
    ptls_encrypt_ticket_t save_ticket = {on_save_ticket};
    ptls_save_ticket_t encrypt_ticket = {on_copy_ticket};

    int ret;
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n";


    //    ctx->omit_end_of_early_data = 0;
    //    ctx->save_ticket = &save_ticket;
    ctx->save_ticket = NULL; /* don't allow further test to update the saved ticket */
                             //    ctx_peer->omit_end_of_early_data = 0;
    ctx_peer->encrypt_ticket = &encrypt_ticket;
    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;

    int is_dhe = 0; /* if enable dhe on psk*/
    if (is_dhe) {
        ctx->require_dhe_on_psk = 1;
        ctx_peer->require_dhe_on_psk = 1;
    }

    client = ptls_new(ctx, 0);
    server = ptls_new(ctx_peer, 1);
    ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
    ptls_buffer_init(&sbuf, sbuf_small, sizeof(sbuf_small));
    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    assert(ctx_peer->max_early_data_size != 0);
    client_hs_prop.client.max_early_data_size = &max_early_data_size;

    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop); /*-->CH*/
    if (ret == PTLS_ERROR_IN_PROGRESS)
        printf("\n##create CH: cbuf.off = %d\n", cbuf.off);

    assert(max_early_data_size == ctx_peer->max_early_data_size);
    ret = ptls_send(client, &cbuf, req, strlen(req)); /*-->early data*/
    if (ret == 0)
        printf("\n##encrypt early message, cbuf.off = %d\n", cbuf.off);

    consumed = cbuf.off; /*cbuf: CH+EE+FIN + early data*/
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop); /* CH-->SH+EE+FIN */
    if(ret == 0) {
        printf("\n##server process CH&early, sbuf.off = %d, consumed = %d\n", sbuf.off, consumed);
        char *server_done = ptls_handshake_is_complete(server) ? "done" : "not complete";
        printf("***server handshake %s\n", server_done);
    }
    assert(consumed < cbuf.off);
    memmove(cbuf.base, cbuf.base+consumed, cbuf.off - consumed);
    cbuf.off -= consumed;

    consumed = cbuf.off;
    ret = ptls_receive(server, &decbuf, cbuf.base, &consumed); /*early data-->decbuf*/
    assert(ret == 0);
    assert(consumed = cbuf.off);
    assert(decbuf.off == strlen(req));
    assert(memcmp(decbuf.base, req, decbuf.off) == 0);
    assert(!ptls_handshake_is_complete(server));
    printf("\n##server received early data: %s\n", decbuf.base);
    cbuf.off = 0;
    decbuf.off = 0;

    ret = ptls_send(server, &sbuf, resp, strlen(resp)); /* enc-->early data reply */
    printf("\n##server send early data reply, sbuf.off = %d\n", sbuf.off);
    assert(ret == 0);

    consumed = sbuf.off; /*sbuf: SH + early data reply*/
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL); /*SH+EE+FIN-->FIN*/
    assert(ret == 0);
    printf("\n##client process SH+EE+FIN, sbuf.off = %d, consumed = %d, cbuf = %d\n", sbuf.off, consumed, cbuf.off);
    char *client_done = ptls_handshake_is_complete(client) ? "done" : "not complete";
    printf("***client handshake %s\n", client_done);
    assert(consumed < sbuf.off);
    memmove(sbuf.base, sbuf.base+consumed, sbuf.off-consumed);
    sbuf.off -= consumed;

    consumed = sbuf.off;
    ret = ptls_receive(client, &decbuf, sbuf.base, &consumed); /*early data reply-->decbuf*/
    assert(ret == 0);
    assert(decbuf.off == strlen(resp));
    assert(memcmp(decbuf.base, resp, strlen(resp)) == 0);
    printf("\n##client decrypt early data reply: %s\n", decbuf.base); /* TODO: weird output with 'x':"HTTP/1.0 200 OK\r\n\r\nhello world\nc"*/
    printf("sbuf.off = %d, consumed = %d, decbuf.off = %d\n", sbuf.off, consumed, decbuf.off);
    decbuf.off = 0;
    sbuf.off = 0;

    consumed = cbuf.off;
    //    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL); /*FIN-->*/
    ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
    assert(ret == 0);
    //    printf("\n##server process FIN, sbuf.off = %d, consumed = %d, cbuf.off = %d\n", sbuf.off, consumed, cbuf.off);
    printf("\n##server process FIN, decbuf.off = %d, consumed = %d, cbuf.off = %d\n", decbuf.off, consumed, cbuf.off);
    char *server_done = ptls_handshake_is_complete(server) ? "done" : "not complete";
    printf("***server handshake %s\n", server_done);
    cbuf.off = 0;

    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    ptls_free(server);
}

void usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -h, --help     Display this help message\n");
    printf("  0              Test full handshake\n");
    printf("  1              Test 0-rtt resumtion with early data\n");
    printf("  2              Test sdp with early data\n");
    printf("  3              Test sdp key gen\n");
    printf("  4              Test sdp key ex\n");
    // Add more options here as needed
}

int main(int argc, char **argv) {

    if ((argc == 1) || (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))) {
        usage(argv[0]);
        return 0;
    }


    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;
    ptls_ech_create_opener_t ech_create_opener = {.cb = create_ech_opener};
    ptls_key_exchange_algorithm_t *ptls_25519_key_excanges[] = {&ptls_openssl_x25519, NULL};

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

    ptls_iovec_t cert;
    setup_certificate(&cert);
    setup_sign_certificate(&openssl_sign_certificate);
    X509_STORE *cert_store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_file());
    int ret = X509_LOOKUP_load_file(lookup, "assets/ca/test-ca.crt", X509_FILETYPE_PEM);
    if (ret != 1) {
        fprintf(stderr, "Failed to load trad CA certificates\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    X509_STORE_set_verify_cb(cert_store, verify_cert_cb);
    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, cert_store);
    /* we should call X509_STORE_free on OpenSSL 1.1 or in prior versions decrement refount then call _free */
    ptls_context_t openssl_ctx = {.random_bytes = ptls_openssl_random_bytes,
                                  .get_time = &ptls_get_time,
                                  .key_exchanges = ptls_openssl_key_exchanges,
//                                  .key_exchanges = ptls_25519_key_excanges,
                                  .cipher_suites = ptls_openssl_cipher_suites_all,
                                  .tls12_cipher_suites = ptls_openssl_tls12_cipher_suites,
                                  .certificates = {&cert, 1},
                                  .ech = {.client = {NULL}},
                                  .sign_certificate = &openssl_sign_certificate.super};
    ptls_context_t openssl_ctx_sha256only = openssl_ctx;
    while (openssl_ctx_sha256only.cipher_suites[0]->hash->digest_size != 32) {
        assert(openssl_ctx.cipher_suites[0]->hash->digest_size == 64 || /* sha512 */
               openssl_ctx.cipher_suites[0]->hash->digest_size == 48);  /* sha384 */
        ++openssl_ctx_sha256only.cipher_suites;
    }
    assert(openssl_ctx_sha256only.cipher_suites[0]->hash->digest_size == 32); /* sha256 */

    ctx = ctx_peer = &openssl_ctx;
    verify_certificate = &openssl_verify_certificate.super;

    /*first run without ECH*/
    ctx_peer->ech.server.create_opener = NULL;
    ctx->ech.client.ciphers = NULL;

    int option = atoi(argv[1]); /*mode = 0(fullhandshake) / 1(earlydata)*/

    switch (option) {
    case 0:
        printf("full handshake test...\n");
        test_handshake_api(); /*test full handshake (generate session ticket)*/
        break;
    case 1:
        printf("early data test...\n");
        test_early_data(); /*test early data*/
        break;
    default:
        printf("invalid input\n");
    }

    return 0;
}