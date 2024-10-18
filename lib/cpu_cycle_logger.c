// cpu_cycle_logger.c
#include "picotls/cpu_cycle_logger.h"
#include <stdio.h>
#include <string.h>

// Define the logs array and log count here
cpu_cycles_log_t logs[MAX_OPERATIONS];
size_t log_count = 0;  // Initialize log_count to 0

// Initialize the logger
void init_logger(void) {
    log_count = 0;  // Reset the log count
}

// Function to log CPU cycles for an operation
void log_cpu_cycles(const char *operation_name, uint64_t start, uint64_t end) {
    if (log_count < MAX_OPERATIONS) {
        strncpy(logs[log_count].operation_name, operation_name, sizeof(logs[log_count].operation_name) - 1);
        logs[log_count].operation_name[sizeof(logs[log_count].operation_name) - 1] = '\0';  // Ensure null-termination
        logs[log_count].start_cycles = start;
        logs[log_count].end_cycles = end;
        log_count++;
//        printf("log count = %zu, operation: %s\n", log_count, operation_name);
    } else {
        printf("Warning: Reached maximum operation log capacity!\n");
    }
}

void reset_logger() {
    log_count = 0;  // Reset the log counter
    memset(logs, 0, sizeof(logs));  // Clear the log buffer
}

// Function to write all logged CPU cycles to a CSV file
void write_cpu_cycles_to_csv(const char *filename, int handshake_count) {
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Failed to open log file");
        return;
    }

    if (handshake_count == 1) {
        fprintf(file, "Handshake,Operation,CPU Cycles\n");
    }

    // Write each logged operation for this handshake
    for (size_t i = 0; i < log_count-4; i++) {
        uint64_t cycles = logs[i].end_cycles - logs[i].start_cycles;
        fprintf(file, "%d,%s,%lu\n", handshake_count, logs[i].operation_name, cycles);
    }

    fclose(file);

    // Clear the logger buffer after writing
    reset_logger();
}
