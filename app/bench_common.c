//
// Created by xinshu on 10/01/25.
//
#include <sys/time.h>
#include <time.h>
#include "bench_common.h"

/* Time in microseconds */
uint64_t bench_time()
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

auth_bench_entry_t sig_list[] =
    {
        {"default", "rsa", rsa_signature_schemes, 1},
        {"default", "ecdsa", secp256r1_signature_schemes, 1},
#if PTLS_OPENSSL_HAVE_ED25519
        {"default", "ed25519", ed25519_signature_schemes, 1},
#endif
        {"oqsprovider", "dilithium2", dilithium2_signature_schemes, 1},
        {"oqsprovider", "dilithium3", dilithium3_signature_schemes, 1},
        {"oqsprovider", "dilithium5", dilithium5_signature_schemes, 1},
};

size_t nb_sig_list = sizeof(sig_list) / sizeof(auth_bench_entry_t);

int bench_basic(uint64_t *x)
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