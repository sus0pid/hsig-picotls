//
// Created by xinshu on 10/01/25.
//

#ifndef HSIG_PICOTLS_BENCH_COMMON_H
#define HSIG_PICOTLS_BENCH_COMMON_H

#include <stdin.h>
#include <openssl/evp.h>
#include "picotls.h"
#include "picotls/openssl.h"

#define ok(expr) \
    do { \
        if (expr) { \
            printf("ok at line %d\n", __LINE__); \
        } else { \
            printf("not ok at line %d\n", __LINE__); \
        } \
    } while (0)

typedef struct st_auth_bench_entry_t {
    const char *provider;
    const char *sig_name;
    const ptls_openssl_signature_scheme_t *schemes;
    int enabled_by_default;
} auth_bench_entry_t;

extern auth_bench_entry_t sig_list[];
extern size_t nb_sig_list;

uint64_t bench_time();
int bench_basic(uint64_t *x);




#endif // HSIG_PICOTLS_BENCH_COMMON_H
