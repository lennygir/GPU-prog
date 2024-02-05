#include <stdio.h>
#include <stdint.h>

#include "../../_utils/conversion_utils.cuh"
#include "chacha20_c.cuh"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_file> <key>\n", argv[0]);
        return 1;
    }

    const char* input_path = argv[1];
    const char* output_path = argv[2];

    const char* key_hex = argv[3];
    const uint8_t* key = hex_to_byte(key_hex);

    chacha20_process_file(input_path, output_path, key);

    printf("File processing complete. Output written to %s\n", output_path);

    return 0;
}