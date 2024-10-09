// rdtsc.h
#ifndef RDTSC_H
#define RDTSC_H

#include <stdint.h>

// Function to measure CPU cycles using rdtsc
static inline uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");  // Serialize
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif // RDTSC_H

