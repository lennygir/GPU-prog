#include <time.h>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>

#include "chacha20.h"
#include "../../_utils/conversion_utils.h"

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

    // Get the file size
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Store the file in a buffer
    clock_t start_alloc = clock();
    uint8_t* buffer = (uint8_t*)malloc(file_size);
    clock_t end_alloc = clock();
    if (buffer == NULL) {
        fprintf(stderr, "Error: Could not allocate memory for the file\n");
        return;
    }
    clock_t start_read = clock();
    size_t bytes_read = fread(buffer, 1, file_size, input_file);
    clock_t end_read = clock();

    // Encrypt the file
    clock_t start_process = clock();

    chacha20_ctx ctx;
    uint8_t nonce[8] = { 0 };
    chacha20_init(&ctx, key, nonce);

    chacha20_process(&ctx, buffer, buffer, bytes_read);
    clock_t end_process = clock();

    // Write the encrypted data to the output file
    clock_t start_write = clock();
    fwrite(buffer, 1, bytes_read, output_file);
    clock_t end_write = clock();

    fclose(input_file);
    fclose(output_file);

    free(buffer);

    clock_t c_end = clock();
    clock_t time_taken = c_end - c_start;

    // Print the time taken
    printf("== METRICS ==\n");
    printf("Alloc: %f\n", (double)(end_alloc - start_alloc) / CLOCKS_PER_SEC * 1000);
    printf("File read: %f\n", (double)(end_read - start_read) / CLOCKS_PER_SEC * 1000);
    printf("Process: %f\n", (double)(end_process - start_process) / CLOCKS_PER_SEC * 1000);
    printf("File write: %f\n", (double)(end_write - start_write) / CLOCKS_PER_SEC * 1000);
    printf("Total: %f\n", (double)time_taken / CLOCKS_PER_SEC * 1000);
}

void chacha20_init(chacha20_ctx* ctx, const uint8_t* key, const uint8_t nonce[8]) {
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

void chacha20_process(chacha20_ctx* ctx, const uint8_t* in, uint8_t* out, size_t size_to_encrypt)
{
    while (size_to_encrypt)
    {
        size_t block_size = MIN(size_to_encrypt, sizeof(ctx->keystream));
        chacha20_block(ctx, ctx->keystream);
        chacha20_xor((uint8_t*)ctx->keystream, &in, &out, block_size);

        size_to_encrypt -= block_size;
    }
}

void chacha20_block(chacha20_ctx* ctx, uint32_t output[16])
{
    uint32_t* const nonce = ctx->init_state + 12; //12 is where the 128 bit counter is
    int i = 10;

    memcpy(output, ctx->init_state, sizeof(ctx->init_state));

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

    if (!++nonce[0] && !++nonce[1] && !++nonce[2]) { ++nonce[3]; }
}

void chacha20_xor(uint8_t* keystream, const uint8_t** in, uint8_t** out, size_t length)
{
    uint8_t* end_keystream = keystream + length;
    do { *(*out)++ = *(*in)++ ^ *keystream++; } while (keystream < end_keystream);
}
