#ifndef CPU_CYCLE_LOGGER_H
#define CPU_CYCLE_LOGGER_H

#include <stdint.h>
#include <stddef.h>

// Structure to store the operation and its CPU cycles
typedef struct {
    char operation_name[64];   // Name of the operation
    uint64_t start_cycles;     // Start time (in CPU cycles)
    uint64_t end_cycles;       // End time (in CPU cycles)
} cpu_cycles_log_t;

#define MAX_OPERATIONS 100  // Maximum number of operations to log

// Declare the log array and count as extern (no initialization here)
extern cpu_cycles_log_t logs[MAX_OPERATIONS];
extern size_t log_count;

// Function to get CPU cycles
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// Initialize the logger
void init_logger(void);

// Log CPU cycles for an operation
void log_cpu_cycles(const char *operation_name, uint64_t start, uint64_t end);

// Write all logged CPU cycles to a CSV file
void write_cpu_cycles_to_csv(const char *filename, int handshake_count);

#endif // CPU_CYCLE_LOGGER_H
