#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../_utils/conversion_utils.cuh"
#include "chacha20.cuh"

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <encrypt | decrypt> <input_file> <output_file> <key>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "encrypt") != 0 && strcmp(argv[1], "decrypt") != 0) {
        fprintf(stderr, "Error: Invalid mode. Use 'encrypt' or 'decrypt'\n");
        return 1;
    }

    const char* input_path = argv[2];
    const char* output_path = argv[3];

    const char* key_hex = argv[4];
    const uint8_t* key = hex_to_byte(key_hex);

    chacha20_process_file(input_path, output_path, key);

    printf("File processing complete. Output written to %s\n", output_path);

    return 0;
}