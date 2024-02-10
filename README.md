# GPU Programming - Encryption and Decryption algorithms

## Description
As part of the GPU Programming course, we decided to analyze performance when implementing encryption/decryption 
algorithms to determine whether it might actually be advantageous to use the GPU in this way for encryption/decryption.

The idea of this project is therefore to try out different implementations of AES_128_ECB and chacha20 in order to
evaluate the differences in performance between a CPU execution and a GPU execution.

## Algorithms implementations
### • AES 128 ECB
- **C** - Simple CPU implementation for AES 128 ECB encryption/decryption
- **Naive** - Simple GPU implementation for AES 128 ECB encryption/decryption
- **Kernel in Kernel** - GPU implementation for AES 128 ECB encryption/decryption where we try to start a new kernel
inside each block to split operations on cells
- **Rcon** - GPU implementation for AES 128 ECB encryption/decryption where we try to use a computed value for the rcon
- **Parallel op** - GPU implementation for AES 128 ECB encryption/decryption where we try to parallelize operations on cells

### • ChaCha20
- **C** - Simple CPU implementation for ChaCha20 encryption/decryption
- **Naive** - Simple GPU implementation for ChaCha20 encryption/decryption
- **Streams** - GPU implementation for ChaCha20 encryption/decryption using streams in order to parallelize CPU computing
(read file) and GPU computing (encryption/decryption)

## How to use?
Each implementation has been built completely separately, so you can compile and run each one separately. In order to 
run them you have two possibilities:
- Compile one of the main.c or main.cu file corresponding to the implementation you want to run
- Run the bash script to compile and run one of the implementation

### Manual compilation
```bash
nvcc -arch=compute_35 -rdc=true ./<algo>/<impl>/main.cu -o main

./main <input_file> <output_file> <key>
```
*The key parameter is not supported for AES implementation*

### Run the bash script
```bash
./exec_project.sh <algo> <impl> <action> <input_file> <output_file> <key>
```
- **algo**: aes or chacha
- **impl**: "c" OR "naive" OR "k_in_k" OR "streams" OR "rcon" OR "parallel_op" OR "shared"
- **action**: "encrypt" OR "decrypt"
- **input_file**: path to the file to encrypt/decrypt
- **output_file**: path to the output file
- **key**: key to use for encryption/decryption (without spaces and the prefix "0x")
  - For AES - 32 characters
  - For ChaCha - 64 characters

## Credits
During this project we used different resources that explain algorithms and possible optimizations. You can find the 
references at the top of the file where some source code used them.