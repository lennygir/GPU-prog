#include <time.h>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include "chacha20_naive.cuh"
#include "../conversion_utils.cuh"

void chacha20_process_file(const char* input_path, const char* output_path, const uint8_t* key) {
    clock_t c_start = clock();
    FILE* input_file = fopen(input_path, "rb");
    FILE* output_file = fopen(output_path, "wb");

    if (input_file == NULL) {
        fprintf(stderr, "Error: Could not open input file %s\n", input_path);
        return;
    }

    if (output_file == NULL) {
        fprintf(stderr, "Error: Could not open output file %s\n", output_path);
        return;
    }

    // Initialize the context
    chacha20_ctx h_ctx;
    uint8_t nonce[8] = { 0 };
    chacha20_init(&h_ctx, key, nonce);

    // Get the file size
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    cudaDeviceProp deviceProp;
    cudaGetDeviceProperties(&deviceProp, 0);

    chacha20_ctx* d_ctx;
    cudaMalloc((chacha20_ctx**)&d_ctx, sizeof(chacha20_ctx));
    cudaMemcpy(d_ctx, &h_ctx, sizeof(chacha20_ctx), cudaMemcpyHostToDevice);

    clock_t c_file_read = 0;
    clock_t c_file_write = 0;
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    float mem_alloc_cuda_ms = 0.f; // Time spent for memory allocation + copy on the device
    float processing_cuda_ms = 0.f; // Time spent for the process

    uint64_t start_counter = 0;
    while (file_size > 0)
    {
        float cuda_event_ms_tmp = 0.f;
        unsigned long long size_to_process = MIN(file_size, deviceProp.totalGlobalMem / 3);

        // Store the file in a buffer
        clock_t start_file_read = clock();
        uint8_t* h_buffer = (uint8_t*)malloc(size_to_process);
        if (h_buffer == NULL) {
            fprintf(stderr, "Error: Could not allocate memory for the file\n");
            exit(EXIT_FAILURE);
        }
        size_t bytes_read = fread(h_buffer, 1, size_to_process, input_file);
        clock_t end_file_read = clock();

        c_file_read += end_file_read - start_file_read;

        cudaEventRecord(start);
        uint8_t* d_buffer;
        cudaMalloc((uint8_t**)&d_buffer, bytes_read);
        cudaMemcpy(d_buffer, h_buffer, bytes_read, cudaMemcpyHostToDevice);
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);
        cudaEventElapsedTime(&cuda_event_ms_tmp, start, stop);
		mem_alloc_cuda_ms += cuda_event_ms_tmp;

        // Determine the number of blocks
        size_t num_chacha20_blocks = bytes_read / sizeof(h_ctx.keystream);
        if (bytes_read % sizeof(h_ctx.keystream) != 0) {
            num_chacha20_blocks++;
        }
        size_t num_threads_per_block = MIN(256, num_chacha20_blocks);
        size_t num_blocks = num_chacha20_blocks / num_threads_per_block;
        if (num_chacha20_blocks % num_threads_per_block != 0) {
            num_blocks++;
        }

        // Encrypt the file
        cudaEventRecord(start);
        chacha20_process << <num_blocks, num_threads_per_block >> > (d_ctx, d_buffer, d_buffer, bytes_read, start_counter);
        cudaDeviceSynchronize();
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);
        cudaEventElapsedTime(&cuda_event_ms_tmp, start, stop);
        processing_cuda_ms += cuda_event_ms_tmp;

        // Handle errors
        cudaError_t error = cudaGetLastError();
        if (error != cudaSuccess) {
            fprintf(stderr, "Error: %s\n", cudaGetErrorString(error));
            exit(EXIT_FAILURE);
        }

        // Copy the encrypted data back to the host
        cudaEventRecord(start);
        cudaMemcpy(h_buffer, d_buffer, bytes_read, cudaMemcpyDeviceToHost);
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);
        cudaEventElapsedTime(&cuda_event_ms_tmp, start, stop);
        mem_alloc_cuda_ms += cuda_event_ms_tmp;

        cudaFree(d_buffer);

        // Append the encrypted data to the output file
        clock_t start_file_write = clock();
        fwrite(h_buffer, 1, bytes_read, output_file);
        clock_t end_file_write = clock();
        c_file_write += end_file_write - start_file_write;

        free(h_buffer);

        file_size -= size_to_process;
        start_counter += num_chacha20_blocks;
    }
    // Free the memory on the device
	cudaFree(d_ctx);

    fclose(input_file);
    fclose(output_file);

    clock_t c_end = clock();
    clock_t c_total = c_end - c_start;

    cudaEventDestroy(start);
    cudaEventDestroy(stop);

	printf("File read: %f ms\n", (double)c_file_read / CLOCKS_PER_SEC * 1000);
	printf("File write: %f ms\n", (double)c_file_write / CLOCKS_PER_SEC * 1000);
	printf("Memory allocation + copy on the device: %f ms\n", mem_alloc_cuda_ms);
    printf("Processing: %f ms\n", processing_cuda_ms);
    printf("Total: %f ms\n", (double)c_total / CLOCKS_PER_SEC * 1000);
}

__host__ void chacha20_init(chacha20_ctx* ctx, const uint8_t* key, const uint8_t nonce[8]) {
    const char constants[17] = "expand 32-byte k";

    ctx->init_state[0] = LE(constants + 0);
    ctx->init_state[1] = LE(constants + 4);
    ctx->init_state[2] = LE(constants + 8);
    ctx->init_state[3] = LE(constants + 12);
    ctx->init_state[4] = LE(key + 0);
    ctx->init_state[5] = LE(key + 4);
    ctx->init_state[6] = LE(key + 8);
    ctx->init_state[7] = LE(key + 12);
    ctx->init_state[8] = LE(key + 16);
    ctx->init_state[9] = LE(key + 20);
    ctx->init_state[10] = LE(key + 24);
    ctx->init_state[11] = LE(key + 28);
    ctx->init_state[12] = 0; // Counter
    ctx->init_state[13] = 0; // Counter
    ctx->init_state[14] = LE(nonce + 0);
    ctx->init_state[15] = LE(nonce + 4);
}

__global__ void chacha20_process(chacha20_ctx* ctx, uint8_t* in, uint8_t* out, size_t size_to_encrypt, uint64_t start_counter)
{
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;

    uint32_t stream[16];

    size_t block_idx_start = thread_id * sizeof(stream);
    size_t block_size = MIN(sizeof(stream), size_to_encrypt - block_idx_start);

    chacha20_block(ctx, stream, start_counter + thread_id);
    chacha20_xor((uint8_t*) stream, in + block_idx_start, out + block_idx_start, block_size);
}

__device__ void chacha20_block(chacha20_ctx* ctx, uint32_t output[16], uint64_t counter)
{
    memcpy(output, ctx->init_state, sizeof(ctx->init_state));
    chacha20_set_counter(output, counter);

    int i = 10;

    while (i--)
    {
        CHACHA20_QUARTER_ROUND(output, 0, 4, 8, 12)
            CHACHA20_QUARTER_ROUND(output, 1, 5, 9, 13)
            CHACHA20_QUARTER_ROUND(output, 2, 6, 10, 14)
            CHACHA20_QUARTER_ROUND(output, 3, 7, 11, 15)
            CHACHA20_QUARTER_ROUND(output, 0, 5, 10, 15)
            CHACHA20_QUARTER_ROUND(output, 1, 6, 11, 12)
            CHACHA20_QUARTER_ROUND(output, 2, 7, 8, 13)
            CHACHA20_QUARTER_ROUND(output, 3, 4, 9, 14)
    }
    for (i = 0; i < 16; ++i)
    {
        uint32_t result = output[i] + ctx->init_state[i];
        FROM_LE((uint8_t*)(output + i), result);
    }
}

__device__ inline void chacha20_xor(uint8_t* keystream, uint8_t* in, uint8_t* out, size_t length)
{
    for (size_t i = 0; i < length; i++)
	{
		out[i] = in[i] ^ keystream[i];
	}
}

__device__ void chacha20_set_counter(uint32_t* state, uint64_t counter)
{
    state[12] = counter & UINT32_C(0xFFFFFFFF);
    state[13] = (counter >> 32);
}