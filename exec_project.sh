#!/bin/bash

declare -A directory_of_algorithm
directory_of_algorithm["aes"]="aes_128_ecb"
directory_of_algorithm["chacha"]="chacha20"

declare -A directory_of_implementation
directory_of_implementation["c"]="C"
directory_of_implementation["naive"]="impl_naive"
directory_of_implementation["k_in_k"]="impl_kernel_in_kernel"
directory_of_implementation["streams"]="impl_naive_streams"
directory_of_implementation["rcon"]="impl_RCON_upgrade"
directory_of_implementation["parallel_op"]="impl_parallel_aes_operations"
directory_of_implementation["shared"]="impl_shared_mem"

# This script is used to execute one of the implementation of the project
# The script takes the following arguments:
#   $1: the name of the algorithm - "aes" OR "chacha"
#   $2: the name of the implementation - "c" OR "naive" OR "k_in_k" OR "streams" OR "rcon" OR "parallel_op"
#   $3: "encrypt" or "decrypt"
#   $4: the path to the input file
#   $5: the path to the output file
#   $6: the key in hex format

# Check if the number of arguments is correct
if [ "$#" -ne 6 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

# Check if the algorithm name is correct
algorithm=$1
if [ "$algorithm" != "aes" ] && [ "$algorithm" != "chacha" ]; then
    echo "Illegal algorithm name"
    exit 1
fi

# Check if the implementation name is correct
implementation=$2
algorithm_implementation_valid=0
if [ "$algorithm" == "aes" ]; then
    if [ "$implementation" == "c" ] || [ "$implementation" == "naive" ] || [ "$implementation" == "k_in_k" ] || [ "$implementation" == "streams" ] || [ "$implementation" == "rcon" ] || [ "$implementation" == "parallel_op" ]; then
        algorithm_implementation_valid=1
    fi
else
    if [ "$implementation" == "c" ] || [ "$implementation" == "naive" ] || [ "$implementation" == "streams" ] || [ "$implementation" == "shared" ]; then
        algorithm_implementation_valid=1
    fi
fi

if [ "$algorithm_implementation_valid" -eq 0 ]; then
    echo "Illegal implementation name for the provided algorithm"
    exit 1
fi

# Check if the operation name is correct
operation=$3
if [ "$operation" != "encrypt" ] && [ "$operation" != "decrypt" ]; then
    echo "Illegal operation name"
    exit 1
fi

input_file=$4
output_file=$5
key_hex=$6

compiler=""
extension=""
if [ "$implementation" == "c" ]; then
    compiler="gcc"
    extension="c"
else
    compiler="nvcc -arch=compute_35 -rdc=true"
    extension="cu"
fi

path_to_main="./${directory_of_algorithm[$algorithm]}/${directory_of_implementation[$implementation]}/main.${extension}"
path_to_implementation=""
if [ "$algorithm" == "aes" ]; then
    path_to_implementation="./${directory_of_algorithm[$algorithm]}/${directory_of_implementation[$implementation]}/aes_core.${extension}"
else
    path_to_implementation="./${directory_of_algorithm[$algorithm]}/${directory_of_implementation[$implementation]}/chacha20.${extension}"
fi

# Build the project
$compiler -o project "./_utils/conversion_utils.${extension}" "$path_to_implementation" "$path_to_main"
if [ $? -ne 0 ]; then
    echo "Failed to build the project, check the error message above"
    exit 1
fi

# Execute the project
./project "$operation" "$input_file" "$output_file" "$key_hex"