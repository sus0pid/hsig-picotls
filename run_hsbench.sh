#!/bin/bash

# Set the variables directly in the script
num_runs=1000          # Number of times to run the program
log_file="hsbench_log.csv" # Log file to store the output

# Loop to run the program multiple times
for ((i=1; i<=num_runs; i++))
do
    echo "Run #$i:"
    ./hsbench $i $log_file
done

