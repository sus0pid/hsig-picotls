// rdtsc.h
#ifndef RDTSC_H
#define RDTSC_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAX_OPERATIONS 100 /*maximum operations you want to log*/

/**
 * Structure to store the operation and its CPU cycles
 */
 typedef struct {
     char operation_name[64];
     uint64_t start_cycles;
     uint64_t end_cycles;
 } cpu_cycles_log_t;

/**
* Array to store the logs
*/
static cpu_cycles_log_t cpu_cycle_logs[MAX_OPERATIONS];
static size_t log_count = 0;

/**
 * Function to measure CPU cycles using rdtsc
 */
static inline uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");  // Serialize
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/**
 * Initialize the logger
 */
static void init_logger(void) {
    log_count = 0; /*Reset the log count*/
}


/**
* Function to log CPU cycles for an operation
*/
static void log_cpu_cycles (const char *operation_name, uint64_t start, uint64_t end) {
    if (log_count < MAX_OPERATIONS) {
        strncpy(cpu_cycle_logs[log_count].operation_name, operation_name,
                sizeof(cpu_cycle_logs[log_count].operation_name)-1);
        cpu_cycle_logs[log_count].operation_name[sizeof(cpu_cycle_logs[log_count].operation_name)-1] = '\0';
        cpu_cycle_logs[log_count].start_cycles = start;
        cpu_cycle_logs[log_count].end_cycles = end;
        log_count++;
    } else {
        printf("Warning: Reached maximum operation log capacity!\n");
    }
}

/**
 * Function to write all logged CPU cycles to a file
 */
 static void write_cpu_cycles_to_file(const char *filename) {
     FILE *file = fopen(filename, "w");
     if (file == NULL) {
         perror("Failed to open log file!\n");
         return;
     }

     for (size_t i=0; i<log_count; i++) {
         uint64_t cycles = cpu_cycle_logs[i].end_cycles - cpu_cycle_logs[i].start_cycles;
         fprintf(file, "Operation: %s, CPU cycles: %lu\n",
                 cpu_cycle_logs[i].operation_name, cycles);
     }

     fclose(file);
 }


#endif // RDTSC_H

