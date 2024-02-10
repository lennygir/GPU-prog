#include <stdio.h>
#include "aes_core.cu"

int main(int argc, char** argv) {
    if(argc != 4) {
        printf("Usage : ./main <input file> <output file> <encrypt | decrypt>\n");
        return 1;
    }

    cudaEvent_t total_start, total_stop;
    cudaEventCreate(&total_start);
    cudaEventCreate(&total_stop);

    cudaEvent_t calculation_start, calculation_stop;
    cudaEventCreate(&calculation_start);
    cudaEventCreate(&calculation_stop);

    cudaEventRecord(total_start, 0);

    // Get output file
    FILE* outputFile = fopen(argv[2], "w");
    if(outputFile == NULL) {
        printf("Error : cannot open file %s\n", argv[2]);
        return 1;
    }

    // Get input file and its size
    FILE* file = fopen(argv[1], "r");
    if(file == NULL) {
        printf("Error : cannot open file %s\n", argv[1]);
        return 1;
    }
    fseek(file, 0, SEEK_END); // seek to end of file
    long fileSizeInByte = ftell(file); // get current file pointer
    fseek(file, 0, SEEK_SET); // seek back to beginning of file

    // Get data and prepare blocks
    int nbBlocks;

    if(strcmp(argv[3], "encrypt") == 0) {
        nbBlocks = fileSizeInByte / BLOCK_SIZE + 1;
        // + 1 : 
        //  - In case the file size is not a multiple of BLOCK_SIZE
        //  - To store the padding size at the end
    } else if(strcmp(argv[3], "decrypt") == 0) {
        nbBlocks = fileSizeInByte / BLOCK_SIZE;
    }

    Aes128Block blocks = (Aes128Block)malloc(BLOCK_SIZE * nbBlocks);
    int indexBlock = 0;
    u_int8_t padding = 0;
    while(!feof(file)) {
        int indexByte = 0;
        Aes128Block block = blocks + (indexBlock * BLOCK_SIZE);
        while(indexByte < BLOCK_SIZE && !feof(file)) {
            block[indexByte] = fgetc(file);
            ++indexByte;
        }
        ++indexBlock;
        if(indexByte == BLOCK_SIZE) {
            padding = 16;
        } else {
            padding = BLOCK_SIZE - indexByte + 1;
        }
    }

    Aes128Block d_blocks;
    cudaMalloc(&d_blocks, BLOCK_SIZE * nbBlocks);

    // Create constant memory
    cudaMemcpyToSymbol(RconMatrix, &CPU_RconMatrix, 255 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(subBytesMatrix, &CPU_subBytesMatrix, 256 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(invSubBytesMatrix, &CPU_invSubBytesMatrix, 256 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(mixColumnsMatrix, &CPU_mixColumnsMatrix, 4 * 4 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(invMixColumnsMatrix, &CPU_invMixColumnsMatrix, 4 * 4 * sizeof(u_int8_t));

    Aes128Key key = generateKey();

    Aes128Key d_key;
    cudaMalloc(&d_key, KEY_SIZE);
    cudaMemcpy(d_key, key, KEY_SIZE, cudaMemcpyHostToDevice);

    int nbCudaBlocks = 1;
    int nbThreadsPerBlock = nbBlocks;
    if(nbBlocks > MAX_THREADS_PER_BLOCK) {
        nbCudaBlocks = nbBlocks / MAX_THREADS_PER_BLOCK;
        if(nbBlocks % MAX_THREADS_PER_BLOCK != 0) {
            ++nbCudaBlocks;
        }
        nbThreadsPerBlock = MAX_THREADS_PER_BLOCK;
    }
    int nbKernelCalls = 1;
    if(nbCudaBlocks > MAX_BLOCKS_PER_KERNEL_CALL) {
        nbKernelCalls = nbCudaBlocks / MAX_BLOCKS_PER_KERNEL_CALL;
        if(nbBlocks % MAX_BLOCKS_PER_KERNEL_CALL != 0) {
            ++nbKernelCalls;
        }
        nbCudaBlocks = MAX_BLOCKS_PER_KERNEL_CALL;
    }

    if(strcmp(argv[3], "encrypt") == 0) {
        // Fill the padding
        for(int indexByte = BLOCK_SIZE * nbBlocks - padding; indexByte < BLOCK_SIZE * nbBlocks - 1; ++indexByte) {
            blocks[indexByte] = 0;
        }
        blocks[BLOCK_SIZE * nbBlocks - 1] = padding;
        padding = 0;

        cudaMemcpy(d_blocks, blocks, BLOCK_SIZE * nbBlocks, cudaMemcpyHostToDevice);

        cudaEventRecord(calculation_start, 0);

        for(int i = 0; i < nbKernelCalls; ++i) {
            encrypt<<<nbCudaBlocks, nbThreadsPerBlock>>>(d_blocks, d_key, nbBlocks, i * nbCudaBlocks * nbThreadsPerBlock);
        }
    } else if(strcmp(argv[3], "decrypt") == 0) {
        cudaMemcpy(d_blocks, blocks, BLOCK_SIZE * nbBlocks, cudaMemcpyHostToDevice);

        cudaEventRecord(calculation_start, 0);

        for(int i = 0; i < nbKernelCalls; ++i) {
            decrypt<<<nbCudaBlocks, nbThreadsPerBlock>>>(d_blocks, d_key, nbBlocks, i * nbCudaBlocks * nbThreadsPerBlock);
        }
    } else {
        printf("Error : unknown command %s\n", argv[3]);
        return 1;
    }

    // Stop the timer
    cudaEventRecord(calculation_stop, 0);
    cudaEventSynchronize(calculation_stop);

    cudaMemcpy(blocks, d_blocks, BLOCK_SIZE * nbBlocks, cudaMemcpyDeviceToHost);

    if(strcmp(argv[3], "decrypt") == 0) {
        // Get the padding size
        padding = blocks[BLOCK_SIZE * nbBlocks - 1];
    }

    // Show CUDA errors
    cudaError_t error = cudaGetLastError();
    if(error != cudaSuccess) {
        printf("CUDA error : %s\n", cudaGetErrorString(error));
        exit(1);
    }

    for(int indexBlock = 0; indexBlock < nbBlocks; ++indexBlock) {
        Aes128Block block = blocks + (indexBlock * BLOCK_SIZE);
        int blockLimit = BLOCK_SIZE;
        if(indexBlock == nbBlocks - 1) {
            blockLimit = BLOCK_SIZE - padding;
        }
        for(int indexByte = 0; indexByte < blockLimit; ++indexByte) {
            fputc(block[indexByte], outputFile);
        }
    }

    // Stop the timer
    cudaEventRecord(total_stop, 0);
    cudaEventSynchronize(total_stop);

    // Display times
    float elapsedTime;

    cudaEventElapsedTime(&elapsedTime, total_start, total_stop);
    printf("Execution (total time): %f ms\n", elapsedTime);

    cudaEventElapsedTime(&elapsedTime, calculation_start, calculation_stop);
    printf("Execution (calculation time): %f ms\n", elapsedTime);

    cudaFree(d_blocks);
    cudaFree(d_key);

    destroyKey(key);

    fclose(file);
    fclose(outputFile);
}