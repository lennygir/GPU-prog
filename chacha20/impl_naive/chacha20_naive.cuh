#ifndef CHACHA20_C_IMPL_H
#define CHACHA20_C_IMPL_H

#include <stdint.h>

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#ifndef CHACHA20_QUARTER_ROUND
#define CHACHA20_QUARTER_ROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

typedef struct
{
    uint32_t init_state[16];
    uint32_t keystream[16];
} chacha20_ctx;

__host__ void chacha20_process_file(const char* input_path, const char* output_path, const uint8_t* key);

__host__ void chacha20_init(chacha20_ctx* ctx, const uint8_t* key, const uint8_t nonce[8]);

__global__ void chacha20_process(chacha20_ctx* ctx, uint8_t* in, uint8_t* out, size_t size_to_encrypt, uint64_t start_counter);

__device__ void chacha20_block(chacha20_ctx* ctx, uint32_t output[16], uint64_t counter);
__device__ inline void chacha20_xor(uint8_t* keystream, uint8_t* in, uint8_t* out, size_t length);
__device__ void chacha20_set_counter(uint32_t* keystream, uint64_t counter);

#endif //CHACHA20_C_IMPL_H
