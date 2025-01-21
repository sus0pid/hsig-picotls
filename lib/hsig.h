//
// Created by xinshu on 17/01/25.
//

#ifndef HSIG_PICOTLS_HSIG_H
#define HSIG_PICOTLS_HSIG_H
#include <stddef.h>
#include <assert.h>
/*
 * hsig interfaces:
 * wots_pkgen()
 * wots_sign()
 * wots_pk_from_sig()
 * sign()
 * verify()
 * config: hash_scheme, w parameter */
#define WOTS_LOG_W 2

/* wots parameters */
typedef struct {
    unsigned int wots_w;
    unsigned int wots_log_w;
    unsigned int wots_l1;
    unsigned int wots_l2;
    unsigned int wots_len;
} hsig_params;

void config_hsig(hsig_params *params) {
    /* n (hash output length) = 256 bit */
    unsigned int precomputedL1[7] = {0, 128, 64, 43, 32, 26, 22};
    unsigned int precomputedL2[7] = {0, 8, 4, 3, 3, 2, 2};

    params->wots_w = 1 << WOTS_LOG_W;
    params->wots_log_w = WOTS_LOG_W;
    params->wots_l1 = precomputedL1[WOTS_LOG_W];
    params->wots_l2 = precomputedL2[WOTS_LOG_W];
    params->wots_len = params->wots_l1 + params->wots_l2;
}

void wots_pkgen(const hsig_params *params, unsigned char *pk) {


}


#endif // HSIG_PICOTLS_HSIG_H
