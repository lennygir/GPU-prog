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

    int nbCudaBlocks = 1;
    int nbThreadsPerBlock = nbBlocks;
    int nbKernelCalls = 1;

    if(nbBlocks > MAX_THREADS_PER_BLOCK) {
        nbCudaBlocks = nbBlocks / MAX_THREADS_PER_BLOCK;
        if(nbBlocks % MAX_THREADS_PER_BLOCK != 0) {
            ++nbCudaBlocks;
        }
        nbThreadsPerBlock = MAX_THREADS_PER_BLOCK;
    }
    if(nbCudaBlocks > MAX_BLOCKS_PER_KERNEL_CALL) {
        nbKernelCalls = nbCudaBlocks / MAX_BLOCKS_PER_KERNEL_CALL;
        if(nbBlocks % MAX_BLOCKS_PER_KERNEL_CALL != 0) {
            ++nbKernelCalls;
        }
        nbCudaBlocks = MAX_BLOCKS_PER_KERNEL_CALL;
    }

    // Create constant memory
    cudaMemcpyToSymbol(RconMatrix, &CPU_RconMatrix, 255 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(subBytesMatrix, &CPU_subBytesMatrix, 256 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(invSubBytesMatrix, &CPU_invSubBytesMatrix, 256 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(mixColumnsMatrix, &CPU_mixColumnsMatrix, 4 * 4 * sizeof(u_int8_t));
    cudaMemcpyToSymbol(invMixColumnsMatrix, &CPU_invMixColumnsMatrix, 4 * 4 * sizeof(u_int8_t));

    // Create the key
    Aes128Key key = generateKey();
    Aes128Key d_key;
    cudaMalloc(&d_key, KEY_SIZE);
    cudaMemcpy(d_key, key, KEY_SIZE, cudaMemcpyHostToDevice);

    u_int8_t padding = 0;

    cudaStream_t* streamsList = (cudaStream_t*)malloc(nbKernelCalls * sizeof(cudaStream_t));
    Aes128Block* d_blocksList = (Aes128Block*)malloc(nbKernelCalls * sizeof(Aes128Block));

    cudaEventRecord(calculation_start, 0);

    const int memorySizeForKernelCall = nbCudaBlocks * nbThreadsPerBlock * BLOCK_SIZE;

    for(int kernelCallCounter = 0; kernelCallCounter < nbKernelCalls; ++kernelCallCounter) {
        Aes128Block blocks = (Aes128Block)malloc(memorySizeForKernelCall);
        // Read the file
        int indexByte = 0;
        while(indexByte < memorySizeForKernelCall && !feof(file)) {
            blocks[indexByte] = fgetc(file);
            ++indexByte;
        }
        if(indexByte == memorySizeForKernelCall) {
            padding = memorySizeForKernelCall;
        } else {
            padding = memorySizeForKernelCall - indexByte + 1;
        }

        // Create the stream
        cudaStream_t newStream;
        cudaStreamCreate(&newStream);
        
        Aes128Block d_blocks;

        if(strcmp(argv[3], "encrypt") == 0) {
            // Fill the padding
            if(kernelCallCounter == nbKernelCalls - 1) {
                for(int indexPadding = memorySizeForKernelCall - padding; indexPadding < memorySizeForKernelCall - 1; ++indexPadding) {
                    blocks[indexPadding] = 0;
                }
                blocks[memorySizeForKernelCall - 1] = padding;
                padding = 0;
            }

            // Copy the block on the device
            cudaMalloc(&d_blocks, memorySizeForKernelCall);
            cudaMemcpyAsync(d_blocks, blocks, memorySizeForKernelCall, cudaMemcpyHostToDevice, newStream);

            // Encrypt the block
            encrypt<<<nbCudaBlocks, nbThreadsPerBlock, 0, newStream>>>(d_blocks, d_key, nbBlocks);
        } else if(strcmp(argv[3], "decrypt") == 0) {
            // Copy the block on the device
            cudaMalloc(&d_blocks, memorySizeForKernelCall);
            cudaMemcpyAsync(d_blocks, blocks, memorySizeForKernelCall, cudaMemcpyHostToDevice, newStream);

            // Decrypt the block
            decrypt<<<nbCudaBlocks, nbThreadsPerBlock, 0, newStream>>>(d_blocks, d_key, nbBlocks);
        }
        // Store the variable and the stream
        streamsList[kernelCallCounter] = newStream;
        d_blocksList[kernelCallCounter] = d_blocks;
    }

    // Wait for the end of the kernel calls
    cudaDeviceSynchronize();

    // Retrieve the data and write them in a file
    for(int kernelCallCounter = 0; kernelCallCounter < nbKernelCalls; ++kernelCallCounter) {
        Aes128Block d_blocks = d_blocksList[kernelCallCounter];
        Aes128Block blocks = (Aes128Block)malloc(memorySizeForKernelCall);

        cudaMemcpyAsync(blocks, d_blocks, memorySizeForKernelCall, cudaMemcpyDeviceToHost, streamsList[kernelCallCounter]);
        int maxToWrite = memorySizeForKernelCall;
        if(strcmp(argv[3], "decrypt") == 0 && kernelCallCounter == nbKernelCalls - 1) {
            // Get the padding size
            padding = blocks[memorySizeForKernelCall - 1];
            maxToWrite -= padding;
        }
        for(int indexByte = 0; indexByte < maxToWrite; ++indexByte) {
            fputc(blocks[indexByte], outputFile);
        }

        cudaStreamDestroy(streamsList[kernelCallCounter]);
        cudaFree(d_blocks);
    }

    // Stop the timer
    cudaEventRecord(calculation_stop, 0);
    cudaEventSynchronize(calculation_stop);

    // Stop the timer
    cudaEventRecord(total_stop, 0);
    cudaEventSynchronize(total_stop);

    // Display times
    float elapsedTime;

    cudaEventElapsedTime(&elapsedTime, total_start, total_stop);
    printf("Execution (total time): %f ms\n", elapsedTime);

    cudaEventElapsedTime(&elapsedTime, calculation_start, calculation_stop);
    printf("Execution (calculation time): %f ms\n", elapsedTime);

    cudaFree(d_key);

    destroyKey(key);

    fclose(file);
    fclose(outputFile);
}